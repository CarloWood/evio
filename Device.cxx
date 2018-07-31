// evio -- Event Driven I/O support.
//
//! @file
//! @brief Definition of namespace evio; class InputDevice and OutputDevice.
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
#include "Device.h"
#include "EventLoopThread.h"
#include "libcwd/buf2str.h"
#ifdef CW_CONFIG_NONBLOCK_SYSV
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#else
#include <unistd.h>     // Needed for fcntl.
#include <fcntl.h>
#endif

namespace evio {

void IOBase::close_fds()
{
  DoutEntering(dc::io, "IOBase::close_fds() [" << (void*)this << ']');
  int input_fd = get_input_fd();
  int output_fd = get_output_fd();
  if (is_open_r())
  {
#ifdef CWDEBUG
    if (!is_valid(input_fd))
      Dout(dc::warning, "Calling IOBase::close_fds on input device with invalid fd = " << input_fd << ".");
#endif
    stop_input_device();
  }
  if (is_open_w())
  {
#ifdef CWDEBUG
    if (!is_valid(output_fd))
      Dout(dc::warning, "Calling IOBase::close_fds on output device with invalid fd = " << output_fd << ".");
#endif
    stop_output_device();
  }
  if (!dont_close())
  {
    if (input_fd != -1)
    {
      DEBUG_ONLY(int err = )
      ::close(input_fd);
      Dout(dc::warning(err)|error_cf, "Failed to close filedescriptor " << input_fd);
    }
    if (output_fd != -1 && output_fd != input_fd)
    {
      DEBUG_ONLY(int err = )
      ::close(output_fd);
      Dout(dc::warning(err)|error_cf, "Failed to close filedescriptor " << output_fd);
    }
  }
  m_flags |= FDS_DEAD;
  if (is_open())
  {
    m_flags &= ~(FDS_W_OPEN | FDS_R_OPEN);
    closed();
  }
}

void InputDevice::init_input_device(int fd)
{
  DoutEntering(dc::io, "InputDevice::init_input_device(" << fd << ") [" << (void*)static_cast<IOBase*>(this) << ']');
  // Don't call init() while the InputDevice is already active.
  ASSERT(!is_active());
  ev_io_init(&m_input_watcher, InputDevice::s_evio_cb, fd, EV_READ);
  m_input_watcher.data = this;
  // init() should be called immediately after opening a file descriptor.
  // In fact, init must be called with a valid, open file descriptor.
  // Here we mark that the file descriptor, that corresponds with reading from this device, is open.
  m_flags |= FDS_R_OPEN;
}

void OutputDevice::init_output_device(int fd)
{
  DoutEntering(dc::io, "OutputDevice::init_output_device(" << fd << ") [" << (void*)static_cast<IOBase*>(this) << ']');
  // Don't call init() while the OutputDevice is already active.
  ASSERT(!is_active());
  ev_io_init(&m_output_watcher, OutputDevice::s_evio_cb, fd, EV_WRITE);
  m_output_watcher.data = this;
  // Here we mark that the file descriptor, that corresponds with writing to this device, is open.
  m_flags |= FDS_W_OPEN;
}

void set_nonblocking(int fd)
{
#ifdef CW_CONFIG_NONBLOCK_POSIX
  int nonb = O_NONBLOCK;
#elif defined(CW_CONFIG_NONBLOCK_BSD)
  int nonb = O_NDELAY;
#endif
#ifdef CW_CONFIG_NONBLOCK_SYSV
  // This portion of code might also apply to NeXT.
  // According to IBMs manual page, this might only work for sockets :/
  #warning "This is not really supported, as I've never been able to test it."
  int res = 1;
  if (ioctl(fd, FIONBIO, &res) < 0)
    perror("ioctl(fd, FIONBIO)");
#else
  int res;
  if ((res = fcntl(fd, F_GETFL)) == -1)
    perror("fcntl(fd, F_GETFL)");
  else if (!(res & nonb) && fcntl(fd, F_SETFL, res | nonb) == -1)
    perror("fcntl(fd, F_SETL, nonb)");
#endif
  return;
}

bool is_valid(int fd)
{
#ifdef _WIN32
  return EV_FD_TO_WIN32_HANDLE (fd) != -1;
#elif defined(CW_CONFIG_NONBLOCK_SYSV)
#error "Not implemented."
#else
  return fcntl(fd, F_GETFL) != -1;
#endif
}

void InputDevice::start_input_device()
{
  DoutEntering(dc::io, "InputDevice::start_input_device() [" << (void*)static_cast<IOBase*>(this) << ']');
  // Call InputDevice::init before calling InputDevice::start.
  ASSERT(m_input_watcher.events != EV_UNDEF);
  // Don't call start twice on a row.
  ASSERT(!is_active());
  // Don't start a device after destructing the last boost::intrusive_ptr that points to it.
  // Did you use boost::intrusive_ptr at all? The recommended way to create a new device is
  // by using evio::create. For example:
  // auto device = evio::create<File<InputDevice>>();
  // device->open("filename.txt");
  ASSERT(!must_be_removed() || ref_count() > 0);        // If this is false then the object is ALREADY deleted!
  // Increment ref count to stop this object from being deleted while being active.
  intrusive_ptr_add_ref(this);
  Dout(dc::io, "Incremented ref count (now " << ref_count() << ") [" << (void*)static_cast<IOBase*>(this) << ']');
  EventLoopThread::start(m_input_watcher);
}

void OutputDevice::start_output_device()
{
  DoutEntering(dc::io, "OutputDevice::start_output_device() [" << (void*)static_cast<IOBase*>(this) << ']');
  // Call OutputDevice::init before calling OutputDevice::start.
  ASSERT(m_output_watcher.events != EV_UNDEF);
  // Don't call start twice on a row.
  ASSERT(!is_active());
  // Increment ref count to stop this object from being deleted while being active.
  intrusive_ptr_add_ref(this);
  Dout(dc::io, "Incremented ref count (now " << ref_count() << ") [" << (void*)static_cast<IOBase*>(this) << ']');
  EventLoopThread::start(m_output_watcher);
}

int OutputDevice::sync()
{
  DoutEntering(dc::io, "OutputDevice::sync() [" << (void*)static_cast<IOBase*>(this) << ']');
  // Don't write to a steam, or flush a stream, after having the last boost::intrusive_ptr that points to the device is deleted.
  ASSERT(!must_be_removed());
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

void InputDevice::stop_input_device()
{
  // We assume that stop_input_device can be called from another thread (than start_output_device)
  // by a callback (of libev), but only after we returned from EventLoopThread::start (or rather,
  // the destruction of the lock object in that function) at which point is_active() will return
  // true.
  if (is_active())
  {
    // It is normal to call stop_output_device() when we are already stopped (ie, from close()),
    // therefore only print that we enter this function when we're actually still active.
    DoutEntering(dc::io, "InputDevice::stop_input_device() [" << (void*)static_cast<IOBase*>(this) << ']');
    ev_io_stop(EV_A_ &m_input_watcher);
    Dout(dc::io, "Decrementing ref count (now " << ref_count() << ") [" << (void*)static_cast<IOBase*>(this) << ']');
    intrusive_ptr_release(this);
  }
  // The filedescriptor, when open, is still considered to be open.
  // A subsequent call to start_input_device() will resume handling it.
}

int InputDevice::get_input_fd()
{
  // Return the raw fd as passed to init_input_device.
  return m_input_watcher.fd;
}

void OutputDevice::stop_output_device()
{
  if (is_active())
  {
    // It is normal to call stop_output_device() when we are already stopped (ie, from close()),
    // therefore only print that we enter this function when we're actually still active.
    DoutEntering(dc::io, "OutputDevice::stop_output_device() [" << (void*)static_cast<IOBase*>(this) << ']');
    ev_io_stop(EV_A_ &m_output_watcher);
    Dout(dc::io, "Decrementing ref count (now " << ref_count() << ") [" << (void*)static_cast<IOBase*>(this) << ']');
    intrusive_ptr_release(this);
  }
  // The filedescriptor, when open, is still considered to be open:
  // A subsequent call to start_output_device() will resume handling it.
}

int OutputDevice::get_output_fd()
{
  // Return the raw fd as passed to init_output_device.
  return m_output_watcher.fd;
}

// Write `m_obuffer' to fd.
void OutputDevice::write_to_fd(int fd)
{
  DoutEntering(dc::io, "OutputDevice::write_to_fd(" << fd << ") [" << (void*)static_cast<IOBase*>(this) << ']');
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
      stop_output_device();	// Buffer is empty: reset fd bit for select(2) call
      return;
    }
#if EWOULDBLOCK != EAGAIN
    register int nr_eagain_errors = 1;
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

void InputDevice::read_from_fd(int fd)
{
  DoutEntering(dc::io, "InputDevice::read_from_fd(" << fd << ") [" << (void*)static_cast<IOBase*>(this) << ']');
  ssize_t space = m_ibuffer->dev2buf_contiguous();
  for (;;)
  {
    // Allocate more space in the buffer if needed.
    if (space == 0 &&
        (space = m_ibuffer->dev2buf_contiguous_forced()) == 0)
    {
      // The buffer is full!
      stop_input_device();              // Stop reading the filedescriptor.
      return;                           // Next time better.
    }

    ssize_t rlen;
    char* new_data = m_ibuffer->dev2buf_ptr();
try_again_read1:
    rlen = ::read(fd, new_data, space);

    if (rlen == 0)                      // EOF reached ?
    {
      Dout(dc::system|dc::evio, "read(" << fd << ", " << (void*)new_data << ", " << space << ") = 0 (EOF)");
      read_returned_zero();
      return;                           // Next time better.
    }

    if (rlen == -1)                     // A read error occured ?
    {
      int err = errno;
      Dout(dc::system|dc::evio|dc::warning|error_cf, "read(" << fd << ", " << (void*)new_data << ", " << space << ") = -1");
      ASSERT(err != EINTR); // FIXME, check for SIGPIPE
      //if (err == EINTR && !SignalServer::caught(SIGPIPE))
      //  goto try_again_read1;
      if (err != EAGAIN && err != EWOULDBLOCK)
        read_error(err);
      return;                           // Next time better.
    }

    m_ibuffer->dev2buf_bump(rlen);

    Dout(dc::system|dc::evio, "read(" << fd << ", " << (void*)new_data << ", " << space << ") = " << rlen);

    data_received(new_data, rlen);

    if (m_ibuffer->buffer_full())
    {
      Dout(dc::evio, "fd " << fd << ": Buffer full!");
      stop_input_device();
      // FIXME: This hangs !?
      return;
    }

    // FIXME: this might happen when the read() was interrupted (POSIX allows to just return the number of bytes
    // read so far). Perhaps we should just try to continue to read until EAGAIN.
    if (rlen < space)   // Did we read everything, or process at least
      return;           //  one message ?

    space = 0;
  }
}

void ReadInputDevice::data_received(char const* new_data, size_t rlen)
{
  DoutEntering(dc::io, "ReadInputDevice::data_received(\"" << buf2str(new_data, rlen) << "\", " << rlen << ") [" << (void*)static_cast<IOBase*>(this) << ']');
  size_t len;
  while ((len = end_of_msg_finder(new_data, rlen)) > 0)
  {
    // We seem to have a complete new message and need to call `decode'
    if (m_ibuffer->has_multiple_blocks())
    {
      // The new message must start at the beginning of the buffer,
      // so the total length of the new message is total size of
      // the buffer minus what was read on top of it.
      size_t msg_len = m_ibuffer->used_size() - (rlen - len);

      if (m_ibuffer->is_contiguous(msg_len))
      {
        MsgBlock msg_block(m_ibuffer->raw_gptr(), msg_len, m_ibuffer->get_get_area_block_node());
        decode(msg_block);
        m_ibuffer->raw_gbump(msg_len);
      }
      else
      {
        MemoryBlock* memory_block = MemoryBlock::create(msg_len);
        AllocTag((void*)memory_block, "read_from_fd: memory block to make message contiguous");
        m_ibuffer->raw_sgetn(memory_block->block_start(), msg_len);
        MsgBlock msg_block(memory_block->block_start(), msg_len, memory_block);
        decode(msg_block);
        memory_block->release();
      }

      ASSERT(m_ibuffer->used_size() == rlen - len);

      m_ibuffer->reduce_buf_if_empty();
      if (is_disabled())
        return;
      rlen -= len;
      if (rlen == 0)
        break; // Buffer is precisely empty anyway.
      new_data += len;
      if ((len = end_of_msg_finder(new_data, rlen)) == 0)
        break; // The rest is not a complete message.
      // See if what is left in the buffer is a message too:
    }
    // At this point we have only one block left.
    // The next loop eats up all complete messages in this last block.
    do
    {
      char* start = m_ibuffer->raw_gptr();
      size_t msg_len = (size_t)(new_data - start) + len;
      MsgBlock msg_block(start, msg_len, m_ibuffer->get_get_area_block_node());
      decode(msg_block);
      m_ibuffer->raw_gbump(msg_len);

      ASSERT(m_ibuffer->used_size() == rlen - len);

      m_ibuffer->reduce_buf_if_empty();
      if (is_disabled())
        return;
      rlen -= len;
      if (rlen == 0)
        break; // Buffer is precisely empty anyway.
      new_data += len;
    } while ((len = end_of_msg_finder(new_data, rlen)) > 0);
    break;
  }
}

} // namespace evio

#if defined(CWDEBUG) && !defined(DOXYGEN)
NAMESPACE_DEBUG_CHANNELS_START
channel_ct evio("EVIO");
NAMESPACE_DEBUG_CHANNELS_END
#endif
