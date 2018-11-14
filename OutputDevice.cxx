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
#include <libcwd/buf2str.h>

namespace evio {

void OutputDevice::init_output_device(int fd)
{
  DoutEntering(dc::io, "OutputDevice::init_output_device(" << fd << ") [" << this << ']');
  // Don't call init() while the OutputDevice is already active.
  ASSERT(!is_active());
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

void OutputDevice::start_output_device()
{
  DoutEntering(dc::io, "OutputDevice::start_output_device() [" << this << ']');
  // Call OutputDevice::init before calling OutputDevice::start.
  ASSERT(m_output_watcher.events != EV_UNDEF);
  if (EventLoopThread::start_if_not_active(m_output_watcher))
  {
    // Increment ref count to stop this object from being deleted while being active.
    intrusive_ptr_add_ref(this);
    Dout(dc::io, "Incremented ref count (now " << ref_count() << ") [" << this << ']');
  }
}

// Read and write threads; possibly other threads.
// This function is thread-safe.
RefCountReleaser OutputDevice::stop_output_device()
{
  RefCountReleaser need_release;
  // It is normal to call stop_output_device() when we are already stopped (ie, from close()),
  // therefore only print that we enter this function when we're actually still active.
  DoutEntering(dc::io(is_active()), "OutputDevice::stop_output_device() [" << this << ']');
  if (EventLoopThread::stop_if_active(m_output_watcher))
  {
    Dout(dc::io, "Passing device " << this << " to RefCountReleaser.");
    need_release = this;
  }
  // The filedescriptor, when open, is still considered to be open:
  // A subsequent call to start_output_device() will resume handling it.
  return need_release;
}

void OutputDevice::disable_output_device()
{
  m_flags |= FDS_W_DISABLED;
  m_disable_release = stop_output_device();
}

void OutputDevice::enable_output_device()
{
  m_flags &= ~FDS_W_DISABLED;
  if (is_writable())
    start_output_device();
  m_disable_release.execute();
}

RefCountReleaser OutputDevice::close_output_device()
{
  DoutEntering(dc::io, "OutputDevice::close_output_device() [" << this << ']');
  RefCountReleaser releaser;
  int output_fd = m_output_watcher.fd;
  if (AI_LIKELY(is_open_w()))
  {
    bool already_closed = (m_flags & (FDS_SAME | FDS_R_OPEN)) == FDS_SAME;
#ifdef CWDEBUG
    if (!already_closed && !is_valid(output_fd))
      Dout(dc::warning, "Calling OutputDevice::close on output device with invalid fd = " << output_fd << ".");
#endif
    releaser = stop_output_device();
    if (!already_closed && !dont_close())
    {
      Dout(dc::io|continued_cf, "close(" << output_fd << ") = ");
      DEBUG_ONLY(int err =) ::close(output_fd);
      Dout(dc::warning(err)|error_cf, "Failed to close filedescriptor " << output_fd);
      Dout(dc::finish, err);
    }
    m_flags &= ~FDS_W_OPEN;
    if (!is_open())
    {
      m_flags |= FDS_DEAD;
      releaser += closed();
    }
  }
  return releaser;
}

// Write `m_obuffer' to fd.
void OutputDevice::write_to_fd(int fd)
{
  DoutEntering(dc::io, "OutputDevice::write_to_fd(" << fd << ") [" << this << ']');
  for (;;) // This runs over all allocated blocks, when we are done we 'return'.
  {
    size_t len; // Available number of characters in current block.
    if (!(len = m_obuffer->buf2dev_contiguous())
        && !(len = m_obuffer->buf2dev_contiguous_forced()))
    {
      Dout(dc::evio, "(Buffer now empty)");
      // Note: A call to `m_obuffer->reduce_buffer_if_empty' is not necessary because
      // `buf2dev_contiguous_forced' calls `force_next_contiguous_number_of_bytes'
      // which calls `ishowmanyc' which calls `iunderflow' which reduces the buffer
      // if necessary.
      stop_output_device();	// Buffer is empty; stop watching the fd.
      return;
    }
#if EWOULDBLOCK != EAGAIN
    int nr_eagain_errors = 1;
try_again_write1:
#endif
    size_t wlen = ::write(fd, m_obuffer->buf2dev_ptr(), len);
    if (wlen == (size_t)-1)
    {
      int err = errno;
#ifdef CWDEBUG
      if (!is_debug_channel())
      {
        Dout(dc::warning|error_cf,
            "write(" << fd << ", " << buf2str(m_obuffer->buf2dev_ptr(), m_obuffer->buf2dev_contiguous()) << ", " << len << ')');
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
      write_error(err);
      return;
    }
    Dout(dc::system, "write(" << fd << ", \"" << buf2str(m_obuffer->buf2dev_ptr(), wlen) << "\", " << len << ") = " << wlen);
    m_obuffer->buf2dev_bump(wlen);
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
  if (AI_UNLIKELY(!is_writable()))
  {
    Dout(dc::warning, "The device is not writable!");
    return -1;
  }
  if (!m_obuffer->buffer_empty() && !is_active())
  {
    start_output_device();
  }
  return 0;
}

} // namespace evio
