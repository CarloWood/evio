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
#include "StreamBuf.h"
#ifdef CWDEBUG
#include <libcwd/buf2str.h>
#endif

namespace evio {

OutputDevice::OutputDevice() : VT_ptr(this), m_output_device_ptr(nullptr), m_obuffer(nullptr)
{
  DoutEntering(dc::evio, "OutputDevice::OutputDevice() [" << this << ']');
  // Mark that OutputDevice is a derived class.
  m_flags |= FDS_W;
  // Give m_output_watcher known values; cause is_active() to return false.
  ev_io_init(&m_output_watcher, OutputDevice::s_evio_cb, -1, EV_UNDEF);
}

// Destructor.
OutputDevice::~OutputDevice()
{
  DoutEntering(dc::evio, "OutputDevice::~OutputDevice() [" << this << ']');
  // Don't delete a device? At most close() it and delete all boost::intrusive_ptr's to it.
  ASSERT(!is_active(SingleThread()));
  if (is_open_w())
    close_output_device();    // This will not delete the object (again) because it isn't active.
  if (m_obuffer)
  {
    // Delete the output buffer if it is no longer needed.
    m_obuffer->release(this);
  }
  // Make sure we detect it if this watcher is used again.
  Debug(m_output_watcher.data = nullptr);
}

void OutputDevice::init_output_device(int fd)
{
  DoutEntering(dc::io, "OutputDevice::init_output_device(" << fd << ") [" << this << ']');
  // Don't call init() while the OutputDevice is already active.
  ASSERT(!is_active(SingleThread()));
  ev_io_init(&m_output_watcher, OutputDevice::s_evio_cb, fd, EV_WRITE);
  m_output_watcher.data = this;
  // Here we mark that the file descriptor, that corresponds with writing to this device, is open.
  m_flags |= FDS_W_OPEN;
  // Keep track of whether or not the output device, if any, has the same fd.
  if ((m_flags & FDS_R_OPEN) && get_input_fd() == fd)
    m_flags |= FDS_SAME;
}

int OutputDevice::get_output_fd() const
{
  // Return the raw fd as passed to init_output_device.
  return m_output_watcher.fd;
}

void OutputDevice::start_output_device(PutThread)
{
  DoutEntering(dc::io, "OutputDevice::start_output_device() [" << this << ']');
  // Call OutputDevice::init before calling OutputDevice::start_output_device.
  ASSERT(m_output_watcher.events != EV_UNDEF);
  // This should be the ONLY place where EventLoopThread::start is called for an OutputDevice!
  // The reason being that we need to enforce that *only* a PutThread starts an output watcher.
  if (EventLoopThread::instance().start(&m_output_watcher, this))
  {
    // Increment ref count to stop this object from being deleted while being active.
    // Object is kept alive until the destruction of the RefCountReleaser returned
    // by either OutputDevice::stop_input_device after that called `need_allow_deletion = this`.
    CWDEBUG_ONLY(int count =) inhibit_deletion();
    Dout(dc::io, "Incremented ref count (now " << (count + 1) << ") [" << this << ']');
  }
}

void OutputDevice::start_output_device(PutThread, utils::FuzzyCondition const& condition)
{
  DoutEntering(dc::io, "OutputDevice::start_output_device(" << condition << ") [" << this << ']');
  // Call OutputDevice::init before calling OutputDevice::start_output_device.
  ASSERT(m_output_watcher.events != EV_UNDEF);
  if (EventLoopThread::instance().start_if(condition, &m_output_watcher, this))
  {
    // Increment ref count to stop this object from being deleted while being active.
    // Object is kept alive until the destruction of the RefCountReleaser returned
    // by either OutputDevice::stop_input_device after that called `need_allow_deletion = this`.
    CWDEBUG_ONLY(int count =) inhibit_deletion();
    Dout(dc::io, "Incremented ref count (now " << (count + 1) << ") [" << this << ']');
  }
}

// Read and write threads; possibly other threads.
// This function is thread-safe.
RefCountReleaser OutputDevice::stop_output_device()
{
  DoutEntering(dc::io, "OutputDevice::stop_output_device() [" << this << ']');
  RefCountReleaser need_allow_deletion;
  if (EventLoopThread::instance().stop(&m_output_watcher))
  {
    Dout(dc::io, "Passing device " << this << " to RefCountReleaser.");
    need_allow_deletion = this;
  }
  // The filedescriptor, when open, is still considered to be open:
  // A subsequent call to start_output_device() will resume handling it.
  return need_allow_deletion;
}

// GetThread only.
RefCountReleaser OutputDevice::stop_output_device(GetThread, utils::FuzzyCondition const& condition)
{
  DoutEntering(dc::io, "OutputDevice::stop_output_device(" << condition << ") [" << this << ']');
  RefCountReleaser need_allow_deletion;
  if (EventLoopThread::instance().stop_if(condition, &m_output_watcher))
  {
    Dout(dc::io, "Passing device " << this << " to RefCountReleaser.");
    need_allow_deletion = this;
  }
  // The filedescriptor, when open, is still considered to be open:
  // A subsequent call to start_output_device() will resume handling it.
  return need_allow_deletion;
}

void OutputDevice::disable_output_device()
{
  int flags = m_flags.fetch_or(FDS_W_DISABLED);
  if ((flags & FDS_W_DISABLED) == 0)
  {
    disable_release_t::wat disable_release_w(m_disable_release);
    *disable_release_w = stop_output_device();
  }
}

void OutputDevice::enable_output_device(PutThread type)
{
  DoutEntering(dc::evio, "OutputDevice::enable_output_device()");
  int flags = m_flags.fetch_and(~FDS_W_DISABLED);
  if ((flags & FDS_W_DISABLED) != 0)
  {
    restart_if_non_active(type);
    disable_release_t::wat disable_release_w(m_disable_release);
    disable_release_w->execute();
  }
}

RefCountReleaser OutputDevice::close_output_device()
{
  DoutEntering(dc::io, "OutputDevice::close_output_device() [" << this << ']');
  RefCountReleaser need_allow_deletion;
  int output_fd = m_output_watcher.fd;
  if (AI_LIKELY(is_open_w()))
  {
    // FDS_SAME is set when this is both, an input device and an output device and is
    // only set after both FDS_R_OPEN and FDS_W_OPEN are set and the file descriptor
    // for reading and writing is the same.
    //
    // Therefore, if FDS_R_OPEN is no longer set then that means that the file
    // descriptor was closed as a result of a call to close_input_device().
    bool already_closed = (m_flags & (FDS_SAME | FDS_R_OPEN)) == FDS_SAME;
#ifdef CWDEBUG
    if (!already_closed && !is_valid(output_fd))
      Dout(dc::warning, "Calling OutputDevice::close_output_device on an output device with invalid fd = " << output_fd << ".");
#endif
    need_allow_deletion = stop_output_device();
    if (!already_closed && !dont_close())
    {
      Dout(dc::io|continued_cf, "close(" << output_fd << ") = ");
      CWDEBUG_ONLY(int err =) ::close(output_fd);
      Dout(dc::warning(err)|error_cf, "Failed to close filedescriptor " << output_fd);
      Dout(dc::finish, err);
    }
    m_flags &= ~FDS_W_OPEN;
    // Remove any pending disable (see the code in close_output_device).
    if ((m_flags.fetch_and(~FDS_W_DISABLED) & FDS_W_DISABLED) != 0)
      disable_release_t::wat(m_disable_release)->execute();
    if (!is_open())
    {
      m_flags |= FDS_DEAD;
      need_allow_deletion += closed();
    }
    else if ((m_flags & FDS_SAME))
      need_allow_deletion += close_input_device();
  }
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
      if (!self->is_debug_channel())
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
  DoutEntering(dc::io, "OutputDevice::sync() [" << this << ']');
  PutThread type;
  if (AI_UNLIKELY(!is_writable()))
  {
    Dout(dc::warning, "The device is not writable!");
    return -1;
  }
  // Advance m_next_egptr, if necessary; making any data written so far available to the Get Thread.
  m_obuffer->sync_egptr();
  utils::FuzzyCondition condition_not_empty([this, type]{
        return !m_obuffer->StreamBufProducer::buffer_empty();
      });
  if ((condition_not_empty && !is_active(type)).is_momentary_true())
    start_output_device(type, condition_not_empty);
  return 0;
}

} // namespace evio
