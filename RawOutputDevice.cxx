/**
 * evio -- A cwm4 git submodule for adding support for buffered, iostream oriented, epoll based I/O.
 *
 * @file
 * @brief Definition of namespace evio; class RawOutputDevice.
 *
 * @Copyright (C) 2018  Carlo Wood.
 *
 * RSA-1024 0x624ACAD5 1997-01-26                    Sign & Encrypt
 * Fingerprint16 = 32 EC A7 B6 AC DB 65 A6  F6 F6 55 DD 1C DC FF 61
 *
 * This file is part of evio.
 *
 * Evio is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Evio is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with evio.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "sys.h"
#include "RawOutputDevice.h"
#include "EventLoopThread.h"
#include "debug.h"
#ifdef CWDEBUG
#include <libcwd/buf2str.h>
#endif

namespace evio {

RawOutputDevice::RawOutputDevice()
{
  DoutEntering(dc::evio, "RawOutputDevice::RawOutputDevice() [" << this << ']');
  // Mark that OutputDevice is a derived class.
  state_t::wat(m_state)->m_flags.set_output_device();
}

// Destructor.
RawOutputDevice::~RawOutputDevice()
{
  DoutEntering(dc::evio, "RawOutputDevice::~RawOutputDevice() [" << this << ']');
  bool is_w_open;
  {
    state_t::rat state_r(m_state);
    // A FileDescriptor whose fd is added to the kernel epoll structure should never be destructed:
    // as long as the fd is registered with the kernel, sooner or later an event will happen
    // and that fd will be returned by epoll_pwait(2) in the form of a struct epoll_event whose
    // `data` member is a pointer to this object!
    // (FileDescriptor* device = static_cast<FileDescriptor*>(event.data.ptr); in EventLoopThread.cxx).
    //
    // One way this can happen is when you simply call `delete device_ptr`. Don't do that.
    // At most close() it and delete all boost::intrusive_ptr's to it.
    //
    // Follow the stack trace up till you find the call to `delete`.
    ASSERT(!state_r->m_flags.is_added());
    is_w_open = state_r->m_flags.is_w_open();
  }
  // An output device must be closed (by calling close_output_device, or close) before
  // it is destructed. We can not call close_output_device here, from the destructor,
  // because that calls a virtual function (closed).
  //
  // In most cases you want to call flush_output_device after the last byte was written
  // to the output device (however, take care not to do that at the moment the device
  // isn't writable yet; e.g. a socket that isn't connected yet. In that case call
  // flush_output_device in the call back of the connected signal (by calling on_connected).
  ASSERT(!is_w_open);
}

void RawOutputDevice::init_output_device(state_t::wat const& state_w)
{
  DoutEntering(dc::io, "RawOutputDevice::init_output_device() [" << this << ']');
  // Don't call init() while the OutputDevice is already active.
  ASSERT(!state_w->m_flags.is_active_output_device());
  // Here we mark that the file descriptor, that corresponds with writing to this device, is open.
  state_w->m_flags.set_w_open();
}

void RawOutputDevice::start_output_device(state_t::wat const& state_w)
{
  DoutEntering(dc::evio, "RawOutputDevice::start_output_device(" << *state_w << ") [" << this << ']');
  // Test for state_w->m_flags.is_writable() before calling this function!
  ASSERT(!state_w->m_flags.is_dead());
  // Call OutputDevice::init before calling OutputDevice::start_output_device and
  // don't call start_output_device when the device was closed.
  ASSERT(state_w->m_flags.is_w_open());
  // This should be the ONLY place where EventLoopThread::start is called for an OutputDevice!
  // The reason being that we need to enforce that *only* a PutThread starts an output watcher.
  EventLoopThread::instance().start(state_w, this);
}

bool RawOutputDevice::start_output_device(state_t::wat const& state_w, utils::FuzzyCondition const& condition)
{
  DoutEntering(dc::evio, "RawOutputDevice::start_output_device(" << *state_w << ", " << condition << ") [" << this << ']');
  // Test for state_w->m_flags.is_writable() before calling this function!
  ASSERT(!state_w->m_flags.is_dead());
  // Call OutputDevice::init before calling OutputDevice::start_output_device.
  ASSERT(state_w->m_flags.is_w_open());
  // Don't call start_output_device with a condition that wasn't transitory_true in the first place.
  // That is, if it is false - don't call this (it will fail anyway) and if it is true then there is
  // no need for the condition (just call start_output_device without condition).
  ASSERT(condition.is_transitory_true());
  return EventLoopThread::instance().start_if(state_w, condition, this);
}

void RawOutputDevice::remove_output_device(int& allow_deletion_count, state_t::wat const& state_w)
{
  DoutEntering(dc::evio, "RawOutputDevice::remove_output_device({" << allow_deletion_count << "}, " << *state_w << ") [" << this << ']');
  EventLoopThread::instance().remove(allow_deletion_count, state_w, this);
  state_w->m_flags.unset_w_flushing();
}

RefCountReleaser RawOutputDevice::flush_output_device()
{
  bool is_open;
  bool need_close;
  {
    state_t::wat state_w(m_state);
    need_close = !state_w->m_flags.is_active_output_device();
    is_open = state_w->m_flags.is_w_open();     // Not already closed?
    if (!need_close)
      state_w->m_flags.set_w_flushing();
  }
  // Only print debug output when the device wasn't already closed before anyway.
  DoutEntering(dc::evio(is_open), "RawOutputDevice::flush_output_device() [" << this << ']');
  // It should not be possible that this device is not open, but is still active.
  ASSERT(is_open || need_close);
  int allow_deletion_count = 0;
  if (need_close && is_open)
    close_output_device(allow_deletion_count);
  return {this, allow_deletion_count};
}

//inline
bool RawOutputDevice::stop_not_flushing_output_device(state_t::wat const& state_w, utils::FuzzyCondition const& condition)
{
  // Don't call this function when the device is 'flushing', instead call stop_output_device(condition).
  ASSERT(!state_w->m_flags.is_w_flushing());
  return EventLoopThread::instance().stop_if(state_w, condition, this);
}

//inline
void RawOutputDevice::stop_not_flushing_output_device(state_t::wat const& state_w)
{
  // Don't call this function when the device is 'flushing', instead call close_output_device.
  ASSERT(!state_w->m_flags.is_w_flushing());
  EventLoopThread::instance().stop(state_w, this);
}

// Read and write threads; possibly other threads.
// This function is thread-safe.
void RawOutputDevice::stop_output_device(int& allow_deletion_count)
{
  DoutEntering(dc::evio, "OutputDevice::stop_output_device({" << allow_deletion_count << "}) [" << this << ']');
  bool need_close = false;
  {
    state_t::wat state_w(m_state);
    need_close = state_w->m_flags.is_w_flushing();
    if (!need_close)
      stop_not_flushing_output_device(state_w);
  }
  if (need_close)
    close_output_device(allow_deletion_count);
  Dout(dc::evio, "flags are now: " << get_flags());
}

// GetThread only.
bool RawOutputDevice::stop_output_device(int& allow_deletion_count, utils::FuzzyCondition const& condition)
{
  DoutEntering(dc::evio, "OutputDevice::stop_output_device({" << allow_deletion_count << "}, " << condition << ") [" << this << ']');
  bool success;
  bool need_close = false;
  {
    state_t::wat state_w(m_state);
    need_close = state_w->m_flags.is_w_flushing();
    if (!need_close)
      success = stop_not_flushing_output_device(state_w, condition);
    else
    {
      success = EventLoopThread::instance().stop_if(state_w, condition, this);
      need_close = !state_w->m_flags.is_active_output_device();
    }
  }
  if (need_close)
    close_output_device(allow_deletion_count);
  Dout(dc::evio, "flags are now: " << get_flags());
  return success;
}

void RawOutputDevice::disable_output_device()
{
  DoutEntering(dc::evio, "OutputDevice::disable_output_device()");
  bool is_flushing = false;
  {
    state_t::wat state_w(m_state);
    if (!state_w->m_flags.is_w_disabled())
    {
      state_w->m_flags.set_w_disabled();
      is_flushing = state_w->m_flags.is_w_flushing();
      if (is_flushing)
      {
        state_w->m_flags.unset_w_flushing();
        disable_is_flushing_t::wat disable_is_flushing_w(m_disable_is_flushing);
        *disable_is_flushing_w = true;
      }
      stop_not_flushing_output_device(state_w);
    }
  }
}

void RawOutputDevice::enable_output_device()
{
  DoutEntering(dc::evio, "OutputDevice::enable_output_device()");
  bool was_disabled;
  {
    state_t::wat state_w(m_state);
    was_disabled = state_w->m_flags.is_w_disabled();
    state_w->m_flags.unset_w_disabled();
    disable_is_flushing_t::wat disable_is_flushing_w(m_disable_is_flushing);
    if (*disable_is_flushing_w)
      state_w->m_flags.set_w_flushing();
  }
  if (was_disabled)
    restart_if_non_active();
}

bool RawOutputDevice::close_output_device(int& allow_deletion_count, state_t::wat const& state_w)
{
  // Only call this function when this is true.
  ASSERT(AI_LIKELY(state_w->m_flags.is_w_open()));

  state_w->m_flags.unset_w_open();
#ifdef CWDEBUG
  if (!is_valid(m_fd))
    Dout(dc::warning, "Calling OutputDevice::close_output_device on an output device with invalid fd = " << m_fd << ".");
#endif
  if (!state_w->m_flags.is_regular_file())
    remove_output_device(allow_deletion_count, state_w);
  else
  {
    state_w->m_flags.unset_w_flushing();
    stop_not_flushing_output_device(state_w);
  }
  // FDS_SAME is set when this is both, an input device and an output device and is
  // only set after both FDS_R_OPEN and FDS_W_OPEN are set.
  //
  // Therefore, if FDS_R_OPEN is still set then we shouldn't close the fd yet.
  if (!(state_w->m_flags.dont_close() || (state_w->m_flags.is_same() && state_w->m_flags.is_r_open())))
  {
    Dout(dc::system|continued_cf, "close(" << m_fd << ") = ");
    CWDEBUG_ONLY(int err =) ::close(m_fd);
    Dout(dc::warning(err)|error_cf, "Failed to close filedescriptor " << m_fd);
    Dout(dc::finish, err);
  }
  // Remove any pending disable, if any (see the code in enable_output_device).
  if (state_w->m_flags.is_w_disabled())
  {
    state_w->m_flags.unset_w_disabled();
    disable_is_flushing_t::wat disable_is_flushing_w(m_disable_is_flushing);
    if (*disable_is_flushing_w)
      state_w->m_flags.set_w_flushing();
  }
  // Mark the device as dead when it has no longer an open file descriptor.
  if (!state_w->m_flags.is_open())
  {
    state_w->m_flags.set_dead();
    return true;
  }
  return false;
}

void RawOutputDevice::close_output_device(int& allow_deletion_count)
{
  bool need_call_to_closed = false;
  state_t::wat state_w(m_state);
  if (AI_LIKELY(state_w->m_flags.is_w_open()))
  {
    // Only print debug output when this function actually does something.
    DoutEntering(dc::evio, "RawInputDevice::close_output_device({" << allow_deletion_count << "}) [" << this << ']');
    need_call_to_closed = close_output_device(allow_deletion_count, state_w);
  }
  if (need_call_to_closed)
    closed(allow_deletion_count);
}

//static
RawOutputDevice::w_close_list_t RawOutputDevice::s_w_close_list;

} // namespace evio
