// evio -- Event Driven I/O support.
//
//! @file
//! @brief Definition of namespace evio; class InputDevice.
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
#include "InputDevice.h"
#include "StreamBuf.h"
#include <libcwd/buf2str.h>

namespace evio {

InputDevice::InputDevice() : m_input_device_events_handler(nullptr), m_ibuffer(nullptr), VT_ptr(this)
{
  DoutEntering(dc::evio, "InputDevice::InputDevice() [" << this << ']');
  // Mark that InputDevice is a derived class.
  m_flags |= FDS_R;
  // Give m_input_watcher known values; cause is_active() to return false.
  ev_io_init(&m_input_watcher, InputDevice::s_evio_cb, -1, EV_UNDEF);
}

InputDevice::~InputDevice()
{
  DoutEntering(dc::evio, "InputDevice::~InputDevice() [" << this << ']');
  // Don't delete a device? At most close() it and delete all boost::intrusive_ptr's to it.
  ASSERT(!is_active());
  if (is_open_r())
    close_input_device();     // This will not delete the object (again) because it isn't active.
  if (m_ibuffer)
  {
    // Delete the input buffer if it is no longer needed.
    m_ibuffer->release(this);
  }
  // Make sure we detect it if this watcher is used again.
  Debug(m_input_watcher.data = nullptr);
}

void InputDevice::init_input_device(int fd)
{
  DoutEntering(dc::evio, "InputDevice::init_input_device(" << fd << ") [" << this << ']');
  // Don't call init() while the InputDevice is already active.
  ASSERT(!is_active());
  ev_io_init(&m_input_watcher, InputDevice::s_evio_cb, fd, EV_READ);
  m_input_watcher.data = this;
  // init() should be called immediately after opening a file descriptor.
  // In fact, init must be called with a valid, open file descriptor.
  // Here we mark that the file descriptor, that corresponds with reading from this device, is open.
  m_flags |= FDS_R_OPEN;
  // Keep track of whether or not the output device, if any, has the same fd.
  if ((m_flags & FDS_W_OPEN) && get_output_fd() == fd)
    m_flags |= FDS_SAME;
}

int InputDevice::get_input_fd() const
{
  // Return the raw fd as passed to init_input_device.
  return m_input_watcher.fd;
}

void InputDevice::start_input_device()
{
  DoutEntering(dc::evio, "InputDevice::start_input_device() [" << this << ']');
  // Call InputDevice::init before calling InputDevice::start.
  ASSERT(m_input_watcher.events != EV_UNDEF);
  // Don't start a device after destructing the last boost::intrusive_ptr that points to it.
  // Did you use boost::intrusive_ptr at all? The recommended way to create a new device is
  // by using evio::create. For example:
  // auto device = evio::create<File<InputDevice>>();
  // device->open("filename.txt");
  ASSERT(!is_destructed());
  // If the device is already active then some other thread already called start_input_device().
  if (EventLoopThread::start_if_not_active(m_input_watcher))
  {
    // Increment ref count to stop this object from being deleted while being active.
    inhibit_deletion();
    Dout(dc::evio, "Incremented ref count (now " << ref_count() << ") [" << this << ']');
  }
}

RefCountReleaser InputDevice::stop_input_device()
{
  RefCountReleaser need_release;
  // We assume that stop_input_device can be called from another thread (than start_output_device)
  // by a callback (of libev), but only after we returned from EventLoopThread::start (or rather,
  // the destruction of the lock object in that function) at which point is_active() will return
  // true.
  // It is normal to call stop_output_device() when we are already stopped (ie, from close()),
  // therefore only print that we enter this function when we're actually still active.
  DoutEntering(dc::evio(is_active()), "InputDevice::stop_input_device() [" << this << ']');
  if (EventLoopThread::stop_if_active(m_input_watcher))
  {
    Dout(dc::evio, "Passing device " << this << " to RefCountReleaser.");
    need_release = this;
  }
  // The filedescriptor, when open, is still considered to be open.
  // A subsequent call to start_input_device() will resume handling it.
  return need_release;
}

void InputDevice::disable_input_device()
{
  m_flags |= FDS_R_DISABLED;
  m_disable_release = stop_input_device();
}

void InputDevice::enable_input_device()
{
  m_flags &= ~FDS_R_DISABLED;
  if (is_readable())
  start_input_device();
  m_disable_release.execute();
}

// FIXME: make this thread-safe
RefCountReleaser InputDevice::close_input_device()
{
  DoutEntering(dc::evio, "InputDevice::close_input_device() [" << this << ']');
  RefCountReleaser releaser;
  int input_fd = m_input_watcher.fd;
  if (AI_LIKELY(is_open_r()))
  {
    // FDS_SAME is set when this is both, an input device and an output device and is
    // only set after both FDS_R_OPEN and FDS_W_OPEN are set and the file descriptor
    // for reading and writing is the same.
    //
    // Therefore, if FDS_W_OPEN is no longer set then that means that the file
    // descriptor was closed as a result of a call to close_output_device().
    bool already_closed = (m_flags & (FDS_SAME | FDS_W_OPEN)) == FDS_SAME;
#ifdef CWDEBUG
    if (!already_closed && !is_valid(input_fd))
      Dout(dc::warning, "Calling InputDevice::close on input device with invalid fd = " << input_fd << ".");
#endif
    releaser = stop_input_device();
    if (!already_closed && !dont_close())
    {
      Dout(dc::evio|continued_cf, "close(" << input_fd << ") = ");
      DEBUG_ONLY(int err =) ::close(input_fd);
      Dout(dc::warning(err)|error_cf, "Failed to close filedescriptor " << input_fd);
      Dout(dc::finish, err);
    }
    m_flags &= ~FDS_R_OPEN;
    // Mark the device as dead when it has no longer any open file descriptor.
    if (!is_open())
    {
      m_flags |= FDS_DEAD;
      releaser += closed();
    }
    else if ((m_flags & FDS_SAME))
      releaser += close_output_device();
  }
  return releaser;
}

// Read thread.
void InputDevice::VT_impl::read_from_fd(InputDevice* self, int fd)
{
  DoutEntering(dc::evio, "InputDevice::read_from_fd(" << fd << ") [" << self << ']');
  ssize_t space = self->m_ibuffer->dev2buf_contiguous();
  for (;;)
  {
    // Allocate more space in the buffer if needed.
    if (space == 0 &&
        (space = self->m_ibuffer->dev2buf_contiguous_forced()) == 0)
    {
      // The buffer is full!
      self->stop_input_device();        // Stop reading the filedescriptor.
      return;                           // Next time better.
    }

    ssize_t rlen;
    char* new_data = self->m_ibuffer->dev2buf_ptr();
//try_again_read1:
    rlen = ::read(fd, new_data, space);

    if (rlen == 0)                      // EOF reached ?
    {
      Dout(dc::system|dc::evio, "read(" << fd << ", " << (void*)new_data << ", " << space << ") = 0 (EOF)");
      self->read_returned_zero();
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
        self->read_error(err);
      return;                           // Next time better.
    }

    self->m_ibuffer->dev2buf_bump(rlen);

    Dout(dc::system|dc::evio, "read(" << fd << ", " << (void*)new_data << ", " << space << ") = " << rlen);

    self->data_received(new_data, rlen);

    if (self->m_ibuffer->buffer_full())
    {
      Dout(dc::evio, "fd " << fd << ": Buffer full!");
      self->stop_input_device();
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

// Read thread.
void InputDevice::VT_impl::data_received(InputDevice* self, char const* new_data, size_t rlen)
{
  DoutEntering(dc::io, "InputDevice::data_received(\"" << buf2str(new_data, rlen) << "\", " << rlen << ") [" << self << ']');
  RefCountReleaser releaser;
  size_t len;
  while ((len = self->m_input_device_events_handler->end_of_msg_finder(new_data, rlen)) > 0)
  {
    // If end_of_msg_finder returns a value larger than 0 then m_input_device_events_handler must be (derived from) a InputDecoder.
    InputDecoder* input_decoder = static_cast<InputDecoder*>(self->m_input_device_events_handler);
    // We seem to have a complete new message and need to call `decode'
    if (self->m_ibuffer->has_multiple_blocks())
    {
      // The new message must start at the beginning of the buffer,
      // so the total length of the new message is total size of
      // the buffer minus what was read on top of it.
      size_t msg_len = self->m_ibuffer->used_size() - (rlen - len);

      if (self->m_ibuffer->is_contiguous(msg_len))
      {
        MsgBlock msg_block(self->m_ibuffer->raw_gptr(), msg_len, self->m_ibuffer->get_get_area_block_node());
        releaser += input_decoder->decode(msg_block);
        self->m_ibuffer->raw_gbump(msg_len);
      }
      else
      {
        MemoryBlock* memory_block = MemoryBlock::create(msg_len);
        AllocTag((void*)memory_block, "read_from_fd: memory block to make message contiguous");
        self->m_ibuffer->raw_sgetn(memory_block->block_start(), msg_len);
        MsgBlock msg_block(memory_block->block_start(), msg_len, memory_block);
        releaser += input_decoder->decode(msg_block);
        memory_block->release();
      }

      ASSERT(self->m_ibuffer->used_size() == rlen - len);

      self->m_ibuffer->reduce_buf_if_empty();
      if (self->is_disabled())
        return;
      rlen -= len;
      if (rlen == 0)
        break; // Buffer is precisely empty anyway.
      new_data += len;
      if ((len = input_decoder->end_of_msg_finder(new_data, rlen)) == 0)
        break; // The rest is not a complete message.
      // See if what is left in the buffer is a message too:
    }
    // At this point we have only one block left.
    // The next loop eats up all complete messages in this last block.
    do
    {
      char* start = self->m_ibuffer->raw_gptr();
      size_t msg_len = (size_t)(new_data - start) + len;
      MsgBlock msg_block(start, msg_len, self->m_ibuffer->get_get_area_block_node());
      releaser += input_decoder->decode(msg_block);
      self->m_ibuffer->raw_gbump(msg_len);

      ASSERT(self->m_ibuffer->used_size() == rlen - len);

      self->m_ibuffer->reduce_buf_if_empty();
      if (self->is_disabled())
        return;
      rlen -= len;
      if (rlen == 0)
        break; // Buffer is precisely empty anyway.
      new_data += len;
    } while ((len = input_decoder->end_of_msg_finder(new_data, rlen)) > 0);
    break;
  }
}

size_t LinkBufferPlus::end_of_msg_finder(char const* UNUSED_ARG(new_data), size_t UNUSED_ARG(rlen))
{
  DoutEntering(dc::io, "LinkBufferPlus::end_of_msg_finder");
  // We're just hijacking InputDevice::data_received here.
  start_output_device();
  return 0;
}

} // namespace evio
