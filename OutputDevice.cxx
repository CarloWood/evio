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
  flags_t::wat(m_flags)->set_writeable_type();
  // Give m_output_watcher known values; cause is_active() to return false.
//  ev_io_init(&m_output_watcher, ..., -1, EV_UNDEF);
}

// Destructor.
OutputDevice::~OutputDevice()
{
  DoutEntering(dc::evio, "OutputDevice::~OutputDevice() [" << this << ']');
  bool is_open_w;
  {
    flags_t::rat flags_r(m_flags);
    // Don't delete a device? At most close() it and delete all boost::intrusive_ptr's to it.
    ASSERT(!flags_r->is_active_output_device());
    is_open_w = flags_r->is_open_w();
  }
  if (is_open_w)
    close_output_device();    // This will not delete the object (again) because it isn't active.
  if (m_obuffer)
  {
    // Delete the output buffer if it is no longer needed.
    m_obuffer->release(this);
  }
}

void OutputDevice::init_output_device(flags_t::wat const& flags_w)
{
  DoutEntering(dc::io, "OutputDevice::init_output_device() [" << this << ']');
  // Don't call init() while the OutputDevice is already active.
  ASSERT(!flags_w->is_active_output_device());
//  ev_io_init(&m_output_watcher, OutputDevice::write_to_fd, m_fd, EV_WRITE);
//  m_output_watcher.data2 = this;
  // Here we mark that the file descriptor, that corresponds with writing to this device, is open.
  flags_w->set_open_w();
}

void OutputDevice::start_output_device(flags_t::wat const& flags_w, PutThread)
{
  DoutEntering(dc::evio, "OutputDevice::start_output_device() [" << this << ']');
  // Call OutputDevice::init before calling OutputDevice::start_output_device.
  ASSERT(flags_w->is_open_w());
  // This should be the ONLY place where EventLoopThread::start is called for an OutputDevice!
  // The reason being that we need to enforce that *only* a PutThread starts an output watcher.
  if (EventLoopThread::instance().start(flags_w, this))
  {
    // Increment ref count to stop this object from being deleted while being active.
    // Object is kept alive until the destruction of the RefCountReleaser returned
    // by either OutputDevice::stop_input_device after that called `need_allow_deletion = this`.
    CWDEBUG_ONLY(int count =) inhibit_deletion();
    Dout(dc::io, "Incremented ref count (now " << (count + 1) << ") [" << this << ']');
  }
}

void OutputDevice::start_output_device(flags_t::wat const& flags_w, PutThread, utils::FuzzyCondition const& condition)
{
  DoutEntering(dc::evio, "OutputDevice::start_output_device(" << condition << ") [" << this << ']');
  // Call OutputDevice::init before calling OutputDevice::start_output_device.
  ASSERT(flags_w->is_open_w());
  if (EventLoopThread::instance().start_if(flags_w, condition, this))
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
RefCountReleaser OutputDevice::stop_output_device(flags_t::wat const& flags_w)
{
  DoutEntering(dc::evio, "OutputDevice::stop_output_device() [" << this << ']');
  RefCountReleaser need_allow_deletion;
  if (EventLoopThread::instance().stop(flags_w, this))
  {
    Dout(dc::io, "Passing device " << this << " to RefCountReleaser.");
    need_allow_deletion = this;
  }
  // The filedescriptor, when open, is still considered to be open:
  // A subsequent call to start_output_device() will resume handling it.
  return need_allow_deletion;
}

// GetThread only.
RefCountReleaser OutputDevice::stop_output_device(flags_t::wat const& flags_w, GetThread, utils::FuzzyCondition const& condition)
{
  DoutEntering(dc::evio, "OutputDevice::stop_output_device(" << condition << ") [" << this << ']');
  RefCountReleaser need_allow_deletion;
  if (EventLoopThread::instance().stop_if(flags_w, condition, this))
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
  flags_t::wat flags_w(m_flags);
  bool was_enabled = !flags_w->is_w_disabled();
  flags_w->disable_w();
  if (was_enabled)
  {
    disable_release_t::wat disable_release_w(m_disable_release);
    *disable_release_w = stop_output_device(flags_w);
  }
}

void OutputDevice::enable_output_device(PutThread type)
{
  DoutEntering(dc::evio, "OutputDevice::enable_output_device()");
  bool was_disabled;
  {
    flags_t::wat flags_w(m_flags);
    was_disabled = flags_w->is_w_disabled();
    flags_w->enable_w();
  }
  if (was_disabled)
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
  flags_t::wat flags_w(m_flags);
  if (AI_LIKELY(flags_w->is_open_w()))
  {
    // FDS_SAME is set when this is both, an input device and an output device and is
    // only set after both FDS_R_OPEN and FDS_W_OPEN are set and the file descriptor
    // for reading and writing is the same.
    //
    // Therefore, if FDS_R_OPEN is no longer set then that means that the file
    // descriptor was closed as a result of a call to close_input_device().
    bool already_closed = flags_w->is_same() && !flags_w->is_open_r();
#ifdef CWDEBUG
    if (!already_closed && !is_valid(m_fd))
      Dout(dc::warning, "Calling OutputDevice::close_output_device on an output device with invalid fd = " << m_fd << ".");
#endif
    need_allow_deletion = stop_output_device(flags_w);
    if (!already_closed && !flags_w->dont_close())
    {
      Dout(dc::system|continued_cf, "close(" << m_fd << ") = ");
      CWDEBUG_ONLY(int err =) ::close(m_fd);
      Dout(dc::warning(err)|error_cf, "Failed to close filedescriptor " << m_fd);
      Dout(dc::finish, err);
    }
    flags_w->unset_open_w();
    // Remove any pending disable (see the code in close_output_device).
    if (flags_w->is_w_disabled())
    {
      flags_w->enable_w();
      disable_release_t::wat(m_disable_release)->execute();
    }
    if (!flags_w->is_open())
    {
      flags_w->set_dead();
      need_allow_deletion += closed();
    }
    else if (flags_w->is_same())
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
      self->stop_output_device(FileDescriptor::flags_t::wat(self->m_flags));	// Buffer is empty; stop watching the fd.
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
      if (!FileDescriptor::flags_t::wat(self->m_flags)->is_debug_channel())
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
  if (AI_UNLIKELY(!flags_t::rat(m_flags)->is_writable()))
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
    start_output_device(flags_t::wat(m_flags), type, condition_not_empty);
  return 0;
}

} // namespace evio
