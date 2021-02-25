/**
 * evio -- A cwm4 git submodule for adding support for buffered, iostream oriented, epoll based I/O.
 *
 * @file
 * @brief Definition of namespace evio; class RawInputDevice.
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
#include "RawInputDevice.h"
#include "EventLoopThread.h"
#include "debug.h"
#ifdef CWDEBUG
#include <libcwd/buf2str.h>
#endif

namespace evio {

RawInputDevice::RawInputDevice()
{
  DoutEntering(dc::evio, "RawInputDevice::RawInputDevice() [" << this << ']');
  // Mark that InputDevice is a derived class.
  state_t::wat(m_state)->m_flags.set_input_device();
}

RawInputDevice::~RawInputDevice()
{
  DoutEntering(dc::evio, "RawInputDevice::~RawInputDevice() [" << this << ']');
  bool is_r_open;
  {
    state_t::wat state_w(m_state);
    // Don't delete a device?! At most close() it and delete all boost::intrusive_ptr's to it.
    ASSERT(!state_w->m_flags.is_active_input_device());
    is_r_open = state_w->m_flags.is_r_open();
  }
  // An input device must be closed (by calling close_input_device, or close) before
  // it is destructed. We can not call close_input_device here, from the destructor,
  // because that calls a virtual function (closed).
  ASSERT(!is_r_open);
}

void RawInputDevice::init_input_device(state_t::wat const& state_w)
{
  DoutEntering(dc::evio, "RawInputDevice::init_input_device() [" << this << ']');
  // Don't call init() while the InputDevice is already active.
  ASSERT(!state_w->m_flags.is_active_input_device());
  // init() should be called immediately after opening a file descriptor.
  // In fact, init must be called with a valid, open file descriptor.
  // Here we mark that the file descriptor, that corresponds with reading from this device, is open.
  state_w->m_flags.set_r_open();
}

bool RawInputDevice::start_input_device(state_t::wat const& state_w, utils::FuzzyCondition const& condition)
{
  DoutEntering(dc::evio, "RawInputDevice::start_input_device(" << *state_w << ", " << condition << ") [" << this << ']');
  // Call InputDevice::init before calling InputDevice::start_input_device.
  ASSERT(state_w->m_flags.is_r_open());
  // Don't call start_input_device with a condition that wasn't transitory_true in the first place.
  // That is, if it is false - don't call this (it will fail anyway) and if it is true then there is
  // no need for the condition (just call start_input_device without condition).
  ASSERT(condition.is_transitory_true());
  return EventLoopThread::instance().start_if(state_w, condition, this);
}

void RawInputDevice::start_input_device(state_t::wat const& state_w)
{
  DoutEntering(dc::evio, "RawInputDevice::start_input_device({" << *state_w << "}) [" << this << ']');
  // Call InputDevice::init before calling InputDevice::start_input_device.
  ASSERT(state_w->m_flags.is_r_open());
  // Don't start a device after destructing the last boost::intrusive_ptr that points to it.
  // Did you use boost::intrusive_ptr at all? The recommended way to create a new device is
  // by using evio::create. For example:
  // auto device = evio::create<File<InputDevice>>();
  // device->open("filename.txt");
  ASSERT(!is_destructed());
  // This should be the ONLY place where EventLoopThread::start is called for an InputDevice.
  // The reason being that we need to enforce that *only* a GetThread starts an input watcher.
  EventLoopThread::instance().start(state_w, this);
}

void RawInputDevice::remove_input_device(int& allow_deletion_count, state_t::wat const& state_w)
{
  DoutEntering(dc::evio, "RawInputDevice::remove_input_device({" << allow_deletion_count << "}, {" << *state_w << "}) [" << this << ']');
  EventLoopThread::instance().remove(allow_deletion_count, state_w, this);
}

bool RawInputDevice::stop_input_device(state_t::wat const& state_w, utils::FuzzyCondition const& condition)
{
  DoutEntering(dc::evio, "RawInputDevice::stop_input_device(" << *state_w << ", " << condition << ") [" << this << ']');
  // Call InputDevice::init before calling InputDevice::stop_input_device.
  ASSERT(state_w->m_flags.is_r_open());
  // Don't call stop_input_device with a condition that wasn't transitory_true in the first place.
  // That is, if it is false - don't call this (it will fail anyway) and if it is true then there is
  // no need for the condition (just call stop_input_device without condition).
  ASSERT(condition.is_transitory_true());
  return EventLoopThread::instance().stop_if(state_w, condition, this);
}

void RawInputDevice::stop_input_device(state_t::wat const& state_w)
{
  // It is normal to call stop_input_device() when we are already stopped (ie, from close()),
  // therefore only print that we enter this function when we're actually still active.
  bool currently_active = state_w->m_flags.is_active_input_device();
  DoutEntering(dc::evio(currently_active), "RawInputDevice::stop_input_device({" << *state_w << "}) [" << this << ']');
  if (currently_active)
    EventLoopThread::instance().stop(state_w, this);
  // The filedescriptor, when open, is still considered to be open.
  // A subsequent call to start_input_device() will resume handling it.
}

bool RawInputDevice::disable_input_device(state_t::wat const& state_w, utils::FuzzyCondition const& condition)
{
  DoutEntering(dc::evio, "RawInputDevice::disable_input_device(" << *state_w << ", " << condition << ") [" << this << ']');
  if (!state_w->m_flags.is_r_disabled())
  {
    state_w->m_flags.set_r_disabled();
    return stop_input_device(state_w, condition);
  }
  // We are indeed stopped now.
  return true;
}

void RawInputDevice::disable_input_device(state_t::wat const& state_w)
{
  DoutEntering(dc::evio, "RawInputDevice::disable_input_device(" << *state_w << ") [" << this << ']');
  if (!state_w->m_flags.is_r_disabled())
  {
    state_w->m_flags.set_r_disabled();
    stop_input_device(state_w);
  }
}

void RawInputDevice::enable_input_device()
{
  DoutEntering(dc::evio, "RawInputDevice::enable_input_device()");
  state_t::wat state_w(m_state);
  bool was_disabled = state_w->m_flags.is_r_disabled();
  state_w->m_flags.unset_r_disabled();
  if (was_disabled)
  {
    // If the device was started while it was disabled, restart it now.
    if (state_w->m_flags.is_readable())
      start_input_device(state_w);
  }
}

bool RawInputDevice::close_input_device(int& allow_deletion_count, state_t::wat const& state_w)
{
  // Only call this function when this is true.
  ASSERT(AI_LIKELY(state_w->m_flags.is_r_open()));

  state_w->m_flags.unset_r_open();
#ifdef CWDEBUG
  if (!is_valid(m_fd))
    Dout(dc::warning, "Calling RawInputDevice::close_input_device on input device with invalid fd = " << m_fd << ".");
#endif
  if (!state_w->m_flags.is_regular_file())
    remove_input_device(allow_deletion_count, state_w);
  else
    stop_input_device(state_w);
  // FDS_SAME is set when this is both, an input device and an output device and is
  // only set after both FDS_R_OPEN and FDS_W_OPEN are set.
  //
  // Therefore, if FDS_W_OPEN is still set then we shouldn't close the fd yet.
  if (!(state_w->m_flags.dont_close() || (state_w->m_flags.is_same() && state_w->m_flags.is_w_open())))
  {
    Dout(dc::system|continued_cf, "close(" << m_fd << ") = ");
    CWDEBUG_ONLY(int err =) ::close(m_fd);
    Dout(dc::warning(err)|error_cf, "Failed to close filedescriptor " << m_fd);
    Dout(dc::finish, err);
  }
  // Remove any pending disable, if any (see the code in enable_input_device).
  state_w->m_flags.unset_r_disabled();
  // Mark the device as dead when it has no longer an open file descriptor.
  if (!state_w->m_flags.is_open())
  {
    state_w->m_flags.set_dead();
    return true;
  }
  return false;
}

void RawInputDevice::close_input_device(int& allow_deletion_count)
{
  bool need_call_to_closed = false;
  state_t::wat state_w(m_state);
  if (AI_LIKELY(state_w->m_flags.is_r_open()))
  {
    // Only print debug output when this function actually does something.
    DoutEntering(dc::evio, "RawInputDevice::close_input_device({" << allow_deletion_count << "}) [" << this << ']');
    need_call_to_closed = RawInputDevice::close_input_device(allow_deletion_count, state_w);
  }
  if (need_call_to_closed)
    closed(allow_deletion_count);
}

} // namespace evio
