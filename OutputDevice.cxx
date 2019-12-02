/**
 * evio -- A cwm4 git submodule for adding support for buffered, iostream oriented, epoll based I/O.
 *
 * @file
 * @brief Definition of namespace evio; class OutputDevice.
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
#include "debug.h"
#include "OutputDevice.h"
#include "EventLoopThread.h"
#include "StreamBuf.h"
#ifdef CWDEBUG
#include <libcwd/buf2str.h>
#endif

namespace evio {

OutputDevice::OutputDevice() : m_source(nullptr), m_obuffer(nullptr)
{
  DoutEntering(dc::evio, "OutputDevice::OutputDevice() [" << this << ']');
  // Mark that OutputDevice is a derived class.
  state_t::wat(m_state)->m_flags.set_output_device();
  // Give m_output_watcher known values; cause is_active() to return false.
//  ev_io_init(&m_output_watcher, ..., -1, EV_UNDEF);
}

// Destructor.
OutputDevice::~OutputDevice()
{
  DoutEntering(dc::evio, "OutputDevice::~OutputDevice() [" << this << ']');
  bool is_w_open;
  {
    state_t::rat state_r(m_state);
    // Don't delete a device? At most close() it and delete all boost::intrusive_ptr's to it.
    ASSERT(!state_r->m_flags.is_added());
    is_w_open = state_r->m_flags.is_w_open();
  }
  if (is_w_open)
  {
    int allow_deletion_count = 0;
    close_output_device(allow_deletion_count);    // This will not delete the object (again) because it isn't added.
    ASSERT(allow_deletion_count == 0);
  }
  if (m_obuffer)
  {
    // Delete the output buffer if it is no longer needed.
    m_obuffer->release(this);
  }
}

void OutputDevice::init_output_device(state_t::wat const& state_w)
{
  DoutEntering(dc::io, "OutputDevice::init_output_device() [" << this << ']');
  // Don't call init() while the OutputDevice is already active.
  ASSERT(!state_w->m_flags.is_active_output_device());
  // Here we mark that the file descriptor, that corresponds with writing to this device, is open.
  state_w->m_flags.set_w_open();
#ifdef DEBUGDEVICESTATS
  m_sent_bytes = 0;
#endif
}

void OutputDevice::start_output_device(state_t::wat const& state_w)
{
  DoutEntering(dc::evio, "OutputDevice::start_output_device(" << *state_w << ") [" << this << ']');
  // Call OutputDevice::init before calling OutputDevice::start_output_device and
  // don't call start_output_device when the device was closed.
  ASSERT(state_w->m_flags.is_w_open());
  // This should be the ONLY place where EventLoopThread::start is called for an OutputDevice!
  // The reason being that we need to enforce that *only* a PutThread starts an output watcher.
  EventLoopThread::instance().start(state_w, this);
}

bool OutputDevice::start_output_device(state_t::wat const& state_w, utils::FuzzyCondition const& condition)
{
  DoutEntering(dc::evio, "OutputDevice::start_output_device(" << *state_w << ", " << condition << ") [" << this << ']');
  // Call OutputDevice::init before calling OutputDevice::start_output_device.
  ASSERT(state_w->m_flags.is_w_open());
  // Don't call start_output_device with a condition that wasn't transitory_true in the first place.
  // That is, if is false - don't call this (it will fail anyway) and if it is true then there is
  // no need for the condition (just call start_output_device without condition).
  ASSERT(condition.is_transitory_true());
  return EventLoopThread::instance().start_if(state_w, condition, this);
}

void OutputDevice::remove_output_device(int& allow_deletion_count, state_t::wat const& state_w)
{
  DoutEntering(dc::evio, "OutputDevice::remove_output_device({" << allow_deletion_count << "}, " << *state_w << ") [" << this << ']');
  EventLoopThread::instance().remove(allow_deletion_count, state_w, this);
  state_w->m_flags.unset_w_flushing();
}

RefCountReleaser OutputDevice::flush_output_device()
{
  DoutEntering(dc::evio, "OutputDevice::flush_output_device() [" << this << ']');
  bool need_close;
  {
    state_t::wat state_w(m_state);
    need_close = !state_w->m_flags.is_active_output_device();
    if (!need_close)
      state_w->m_flags.set_w_flushing();
  }
  int allow_deletion_count = 0;
  if (need_close)
    close_output_device(allow_deletion_count);
  return {this, allow_deletion_count};
}

//inline
bool OutputDevice::stop_not_flushing_output_device(state_t::wat const& state_w, utils::FuzzyCondition const& condition)
{
  // Don't call this function when the device is 'flushing', instead call stop_output_device(condition).
  ASSERT(!state_w->m_flags.is_w_flushing());
  return EventLoopThread::instance().stop_if(state_w, condition, this);
}

//inline
void OutputDevice::stop_not_flushing_output_device(state_t::wat const& state_w)
{
  // Don't call this function when the device is 'flushing', instead call close_output_device.
  ASSERT(!state_w->m_flags.is_w_flushing());
  EventLoopThread::instance().stop(state_w, this);
}

// Read and write threads; possibly other threads.
// This function is thread-safe.
void OutputDevice::stop_output_device(int& allow_deletion_count)
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
}

// GetThread only.
bool OutputDevice::stop_output_device(int& allow_deletion_count, utils::FuzzyCondition const& condition)
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
  return success;
}

void OutputDevice::disable_output_device()
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

void OutputDevice::enable_output_device()
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

void OutputDevice::close_output_device(int& allow_deletion_count)
{
  DoutEntering(dc::io, "OutputDevice::close_output_device({" << allow_deletion_count << "})"
#ifdef DEBUGDEVICESTATS
      " [sent_bytes = " << m_sent_bytes << "]"
#endif
      "[" << this << ']');

  bool need_call_to_closed = false;
  {
    state_t::wat state_w(m_state);
    if (AI_LIKELY(state_w->m_flags.is_w_open()))
    {
      state_w->m_flags.unset_w_open();
#ifdef CWDEBUG
      if (!is_valid(m_fd))
        Dout(dc::warning, "Calling OutputDevice::close_output_device on an output device with invalid fd = " << m_fd << ".");
#endif
      remove_output_device(allow_deletion_count, state_w);
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
        need_call_to_closed = true;
      }
    }
  }
  if (need_call_to_closed)
    closed(allow_deletion_count);
}

// Write `m_obuffer' to fd.
// BRT
void OutputDevice::write_to_fd(int& allow_deletion_count, int fd)
{
  DoutEntering(dc::io, "OutputDevice::write_to_fd({" << allow_deletion_count << "}, " << fd << ") [" << this << ']');
#ifdef CWDEBUG
  // Call set_source() on an OutputDevice before starting it.
  if (!m_obuffer)
    DoutFatal(dc::core, "Error: m_obuffer == nullptr; call set_source() on an OutputDevice before starting it.");
#endif
  OutputBuffer* const obuffer = m_obuffer;
  for (;;) // This runs over all allocated blocks, when we are done we 'return'.
  {
    size_t len; // Available number of characters in current block.
    if (!(len = obuffer->buf2dev_contiguous())
        && !(len = obuffer->buf2dev_contiguous_forced()))
    {
      Dout(dc::evio, "(Buffer now empty)");
      // Note: A call to `m_obuffer->reduce_buffer_if_empty' is not necessary because
      // `buf2dev_contiguous_forced' calls `force_next_contiguous_number_of_bytes'
      // which only returns 0 when `underflow_a' returned EOF in which case that already
      // reduced the buffer if necessary.
      //
      // However, even though the buffer was JUST empty - it is possible that right
      // here another thread that wrote new data to the buffer calls sync(), which
      // would be ignored because we didn't reset the ACTIVE bit yet. Although unlikely
      // it could cause a call to sync() to be lost. And if no new data is written,
      // then this data would never be flushed out.
      //
      // Therefore, call stop_output_device with a condition that re-checks if the
      // buffer is really empty inside the critical area of m_state.
      utils::FuzzyCondition condition_nothing_to_get([obuffer]{
          return obuffer->StreamBufConsumer::nothing_to_get();
      });
      obuffer->restart_input_device_if_needed();
      // When buf2dev_contiguous_forced() returned zero then the buffer is empty.
      // So, it is unlikely that a microsecond later it isn't anymore but we're
      // not allowed to call stop_output_device with a false condition (simply
      // because it makes no sense).
      if (AI_UNLIKELY(condition_nothing_to_get.is_momentary_false()))
        continue;
      // If during the cannonical test the buffer isn't empty anymore, continue reading.
      if (AI_UNLIKELY(!stop_output_device(allow_deletion_count, condition_nothing_to_get)))
        continue;
      return;
    }
#if EWOULDBLOCK != EAGAIN
    int nr_eagain_errors = 1;
#endif
    ssize_t wlen;
    for (;;)    // EINTR / EAGAIN loop.
    {
      wlen = ::write(fd, obuffer->buf2dev_ptr(), len);
      if (AI_LIKELY(wlen != -1))
        break;

      int err = errno;
      int const is_debug_channel =
#ifdef CWDEBUG
        FileDescriptor::state_t::wat(m_state)->m_flags.is_debug_channel();
#else
        false;
#endif
      // It can happen that the fd is already closed by another thread, as a result of a read event on this fd.
      if (err == EBADF && FileDescriptor::state_t::wat(m_state)->m_flags.is_dead())
      {
        if (!is_debug_channel)
          Dout(dc::evio, "Leaving OutputDevice::write_to_fd() because fd was already closed.");
        return;
      }
#ifdef CWDEBUG
      if (!is_debug_channel)
        Dout(dc::system|error_cf, "write(" << fd << ", " << buf2str(obuffer->buf2dev_ptr(), obuffer->buf2dev_contiguous()) << ", " << len << ") = -1");
      else
        std::cerr << "OutputDevice::write_to_fd(): WARNING: write error to debug channel: " << strerror(err) << std::endl;
#endif
      if (err == EINTR)
        continue;     // Try the same write again.
      if (err == EWOULDBLOCK)
      {
        // We can't just leave this function in this case because regular files aren't
        // event driven. Right now I'm assuming that this will never happen because
        // the whole reason that regular files are not event driven by epoll (aka, do
        // not support epoll) is supposedly because they CAN'T block(?). If this DOES
        // happen then I can't think of another solution then to immediately call write(2)
        // again though.
        ASSERT(!FileDescriptor::state_t::wat(m_state)->m_flags.is_regular_file());
        return;
      }
#if EWOULDBLOCK != EAGAIN
      if (err == EAGAIN)
      {
        if (nr_eagain_errors--)
          continue;   // Try the same write again.
        // See above.
        ASSERT(!FileDescriptor::state_t::wat(m_state)->m_flags.is_regular_file());
        return;
      }
#endif
      write_error(allow_deletion_count, err);
      return;
    }

    Dout(dc::system, "write(" << fd << ", \"" << buf2str(obuffer->buf2dev_ptr(), wlen) << "\", " << len << ") = " << wlen);
    obuffer->buf2dev_bump(wlen);
#ifdef DEBUGDEVICESTATS
    m_sent_bytes += wlen;
#endif
    Dout(dc::evio|continued_cf, "Wrote " << wlen << " bytes to fd " << fd
#ifdef DEBUGDEVICESTATS
        << " [total sent now " << m_sent_bytes << " bytes]"
#endif
    );
    obuffer->restart_input_device_if_needed();
    if ((size_t)wlen < len)
    {
      // This means we can't write more at the moment. In the case of regular
      // files that should really be true. For other cases it would be ok when
      // that is not the case: then we will get a new EPOLLOUT event.
      Dout(dc::finish, " (Tried to write " << len << " bytes) [" << this << ']');
      return;			// We wrote as much as currently possible.
    }
    Dout(dc::finish, " [" << this << ']');
  }
}

int OutputDevice::sync()
{
  DoutEntering(dc::evio, "OutputDevice::sync() [" << this << ']');
  PutThread type;
  if (AI_UNLIKELY(!state_t::rat(m_state)->m_flags.is_writable()))
  {
    Dout(dc::warning, "The device is not writable!");
    return -1;
  }
  // Advance m_last_pptr, if necessary; making any data written so far available to the consumer thread.
  m_obuffer->sync_egptr();
  utils::FuzzyCondition condition_not_empty([this]{
        return !m_obuffer->StreamBufProducer::nothing_to_get();
      });
  if (!condition_not_empty.is_momentary_true())
    Dout(dc::warning, "condition_not_empty is not momentary_true");
  else if (!(!is_active(type)).is_momentary_true())
    Dout(dc::warning, "!is_active(type) is not momentary_true");
  if ((condition_not_empty && !is_active(type)).is_momentary_true())
    start_output_device(state_t::wat(m_state), condition_not_empty);
  return 0;
}

} // namespace evio
