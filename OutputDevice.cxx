// evio -- Event Driven I/O support.
//
//! @file
//! @brief Definition of namespace evio; class OutputDevice.
//
// Copyright (C) 2018 Carlo Wood.
//
// RSA-1024 0x624ACAD5 1997-01-26                    Sign & Encrypt
// Fingerprint16 = 32 EC A7 B6 AC DB 65 A6  F6 F6 55 DD 1C DC FF 61
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

#include "sys.h"
#include "debug.h"
#include "OutputDevice.h"
#include "EventLoopThread.h"
#include "StreamBuf.h"
#ifdef CWDEBUG
#include <libcwd/buf2str.h>
#endif

namespace evio {

OutputDevice::OutputDevice() : VT_ptr(this), m_output_device_ptr(nullptr), m_obuffer(nullptr)
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
    close_output_device();    // This will not delete the object (again) because it isn't added.
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
//  ev_io_init(&m_output_watcher, OutputDevice::write_to_fd, m_fd, EV_WRITE);
//  m_output_watcher.data2 = this;
  // Here we mark that the file descriptor, that corresponds with writing to this device, is open.
  state_w->m_flags.set_w_open();
}

void OutputDevice::start_output_device(state_t::wat const& state_w)
{
  DoutEntering(dc::evio, "OutputDevice::start_output_device() [" << this << ']');
  // Call OutputDevice::init before calling OutputDevice::start_output_device.
  ASSERT(state_w->m_flags.is_w_open());
  // This should be the ONLY place where EventLoopThread::start is called for an OutputDevice!
  // The reason being that we need to enforce that *only* a PutThread starts an output watcher.
  if (EventLoopThread::instance().start(state_w, this))
  {
    // Increment ref count to stop this object from being deleted while being active.
    // Object is kept alive until the destruction of the RefCountReleaser returned
    // by either OutputDevice::stop_input_device after that called `need_allow_deletion = this`.
    CWDEBUG_ONLY(int count =) inhibit_deletion();
    Dout(dc::io, "Incremented ref count (now " << (count + 1) << ") [" << this << ']');
  }
}

void OutputDevice::start_output_device(state_t::wat const& state_w, utils::FuzzyCondition const& condition)
{
  DoutEntering(dc::evio, "OutputDevice::start_output_device(" << condition << ") [" << this << ']');
  // Call OutputDevice::init before calling OutputDevice::start_output_device.
  ASSERT(state_w->m_flags.is_w_open());
  if (EventLoopThread::instance().start_if(state_w, condition, this))
  {
    // Increment ref count to stop this object from being deleted while being active.
    // Object is kept alive until the destruction of the RefCountReleaser returned
    // by either OutputDevice::stop_input_device after that called `need_allow_deletion = this`.
    CWDEBUG_ONLY(int count =) inhibit_deletion();
    Dout(dc::io, "Incremented ref count (now " << (count + 1) << ") [" << this << ']');
  }
}

RefCountReleaser OutputDevice::remove_output_device(state_t::wat const& state_w)
{
  DoutEntering(dc::evio, "OutputDevice::remove_output_device() [" << this << ']');
  RefCountReleaser needs_allow_deletion;
  if (EventLoopThread::instance().remove(state_w, this))
    needs_allow_deletion = this;
  state_w->m_flags.unset_w_flushing();
  return needs_allow_deletion;
}

RefCountReleaser OutputDevice::flush_output_device()
{
  DoutEntering(dc::evio, "OutputDevice::flush_output_device() [" << this << ']');
  RefCountReleaser needs_allow_deletion;
  bool need_close;
  {
    state_t::wat state_w(m_state);
    need_close = !state_w->m_flags.is_active_output_device();
    if (!need_close)
      state_w->m_flags.set_w_flushing();
  }
  if (need_close)
    needs_allow_deletion = close_output_device();
  return needs_allow_deletion;
}

//inline
void OutputDevice::stop_output_device(state_t::wat const& state_w, utils::FuzzyCondition const& condition)
{
  // Don't call this function when the device is 'flushing', instead call close_output_device(condition).
  ASSERT(!state_w->m_flags.is_w_flushing());
  EventLoopThread::instance().stop_if(state_w, condition, this);
}

//inline
void OutputDevice::stop_output_device(state_t::wat const& state_w)
{
  // Don't call this function when the device is 'flushing', instead call close_output_device().
  ASSERT(!state_w->m_flags.is_w_flushing());
  EventLoopThread::instance().stop(state_w, this);
}

// Read and write threads; possibly other threads.
// This function is thread-safe.
RefCountReleaser OutputDevice::stop_output_device()
{
  RefCountReleaser need_allow_deletion;
  bool need_close = false;
  {
    state_t::wat state_w(m_state);
    need_close = state_w->m_flags.is_w_flushing();
    if (!need_close)
      stop_output_device(state_w);
  }
  if (need_close)
    need_allow_deletion = close_output_device();
  return need_allow_deletion;
}

// GetThread only.
RefCountReleaser OutputDevice::stop_output_device(utils::FuzzyCondition const& condition)
{
  RefCountReleaser need_allow_deletion;
  bool need_close = false;
  {
    state_t::wat state_w(m_state);
    need_close = state_w->m_flags.is_w_flushing();
    if (!need_close)
      stop_output_device(state_w, condition);
    else
    {
      EventLoopThread::instance().stop_if(state_w, condition, this);
      need_close = !state_w->m_flags.is_active_output_device();
    }
  }
  if (need_close)
    need_allow_deletion = close_output_device();
  return need_allow_deletion;
}

void OutputDevice::disable_output_device()
{
  bool need_close = false;
  {
    state_t::wat state_w(m_state);
    if (!state_w->m_flags.is_w_disabled())
    {
      state_w->m_flags.set_w_disabled();
      need_close = state_w->m_flags.is_w_flushing();
      if (!need_close)
        stop_output_device(state_w);
    }
  }
  if (need_close)
  {
    disable_release_t::wat disable_release_w(m_disable_release);
    *disable_release_w = close_output_device();
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
  }
  if (was_disabled)
  {
    restart_if_non_active();
    disable_release_t::wat disable_release_w(m_disable_release);
    disable_release_w->execute();
  }
}

RefCountReleaser OutputDevice::close_output_device()
{
  DoutEntering(dc::io, "OutputDevice::close_output_device() [" << this << ']');
  RefCountReleaser need_allow_deletion;
  bool need_call_to_closed = false;
  {
    state_t::wat state_w(m_state);
    if (AI_LIKELY(state_w->m_flags.is_w_open()))
    {
      state_w->m_flags.unset_w_open();
      Dout(dc::io, "Passing device " << this << " to RefCountReleaser.");
#ifdef CWDEBUG
      if (!is_valid(m_fd))
        Dout(dc::warning, "Calling OutputDevice::close_output_device on an output device with invalid fd = " << m_fd << ".");
#endif
      need_allow_deletion = remove_output_device(state_w);
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
      // Remove any pending disable (see the code in close_output_device).
      if (state_w->m_flags.is_w_disabled())
      {
        state_w->m_flags.unset_w_disabled();
        disable_release_t::wat(m_disable_release)->execute();
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
    need_allow_deletion += closed();
  return need_allow_deletion;
}

// Write `m_obuffer' to fd.
// BRT
void OutputDevice::VT_impl::write_to_fd(OutputDevice* self, int fd)
{
  DoutEntering(dc::io, "OutputDevice::write_to_fd(" << fd << ") [" << self << ']');
  OutputBuffer* const obuffer = self->m_obuffer;
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
      self->stop_output_device();	// Buffer is empty; stop watching the fd.
      return;
    }
#if EWOULDBLOCK != EAGAIN
    int nr_eagain_errors = 1;
try_again_write1:
#endif
    size_t wlen = ::write(fd, obuffer->buf2dev_ptr(), len);
    if (wlen == (size_t)-1)
    {
      int err = errno;
#ifdef CWDEBUG
      if (!FileDescriptor::state_t::wat(self->m_state)->m_flags.is_debug_channel())
      {
        Dout(dc::warning|error_cf,
            "write(" << fd << ", " << buf2str(obuffer->buf2dev_ptr(), obuffer->buf2dev_contiguous()) << ", " << len << ')');
      }
      else
        std::cerr << "OutputDevice::write_to_fd(): WARNING: write error to debug channel: " << strerror(err) << std::endl;
#endif
      ASSERT(err != EINTR); // FIXME, check for SIGPIPE
      //if (errno == EINTR && !SignalServer::caught(SIGPIPE))
      //  continue;
      if (err == EWOULDBLOCK)
        return;
#if EWOULDBLOCK != EAGAIN
      if (err == EAGAIN)
      {
        if (nr_eagain_errors--)
          goto try_again_write1;
        return;
      }
#endif
      self->write_error(err);
      return;
    }
    Dout(dc::system, "write(" << fd << ", \"" << buf2str(obuffer->buf2dev_ptr(), wlen) << "\", " << len << ") = " << wlen);
    obuffer->buf2dev_bump(wlen);
    Dout(dc::evio, "Wrote " << wlen << " bytes to fd " << fd << '.' );
    if (wlen < len)
    {
      Dout(dc::evio, "(Tried to write " << len << " bytes).");
      return;			// We wrote as much as currently possible.
    }
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
  // Advance m_next_egptr, if necessary; making any data written so far available to the Get Thread.
  m_obuffer->sync_egptr();
  utils::FuzzyCondition condition_not_empty([this]{
        return !m_obuffer->StreamBufProducer::buffer_empty();
      });
  if ((condition_not_empty && !is_active(type)).is_momentary_true())
    start_output_device(state_t::wat(m_state), condition_not_empty);
  return 0;
}

} // namespace evio
