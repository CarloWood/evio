// evio -- Event Driven I/O support.
//
//! @file
//! @brief Declaration of class OutputDevice.
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

#pragma once

#include "FileDescriptor.h"
#include "EventLoopThread.h"
#include "libev-4.24/ev.h"
#include "StreamBuf.h"

namespace evio {

class OutputDevicePtr;
class OutputBuffer;

class OutputDevice : public virtual FileDescriptor
{
 private:
  //---------------------------------------------------------------------------
  // Inferface with libev.
  //

  ev_io m_output_watcher;               // The watcher.
  RefCountReleaser m_disable_release;

 protected:
  //---------------------------------------------------------------------------
  // The output buffer
  //

  OutputDevicePtr* m_output_device_ptr; // A pointer to an object that points back to us.
  OutputBuffer* m_obuffer;              // A pointer to the output buffer.

 protected:
  void start_output_device();           friend class OutputDevicePtr;
  RefCountReleaser stop_output_device();
  void disable_output_device();
  void enable_output_device();
  int get_output_fd() const;

 protected:
  OutputDevice();
  ~OutputDevice();

  // Disallow copy constructing.
  OutputDevice(OutputDevice const&) = delete;

 private:
  // Override base class member function.
  void init_output_device(int fd) override;

  // The call back used by libev.
  static void s_evio_cb(EV_P_ ev_io* w, int)
  {
    // Release the mutex on 'loop' while calling an external function.
    auto release_lock = EventLoopThread::temporary_release(EV_A);
    static_cast<OutputDevice*>(w->data)->write_to_fd(w->fd);
  }

 public:
  //---------------------------------------------------------------------------
  // Public accessors:
  //

#if 0
  // Supposed to be used for passing it to other device constructors.
  Buf2Dev* rddbbuf() const { return m_obuffer; }
#endif

  // Returns true if our watcher is linked in with libev.
  bool is_active() const { return ev_is_active(&m_output_watcher); }

  // FIXME: make this thread-safe.
  void restart_if_non_active()
  {
    // This function should be called only from Buf2Dev::flush, and therefore be an output device.
    ASSERT(writable_type());
    //FIXME: this looks like a race condition. Two different threads can call this function.
    if (is_writable() && !is_active())
      start_output_device();
  }

 public:
  //---------------------------------------------------------------------------
  // Public manipulators:
  //

  template<typename... Args>
  void output(OutputDevicePtr& output_device_ptr, Args... output_buffer_arguments);

  template<typename DEVICE, typename... Args>
  void output(boost::intrusive_ptr<DEVICE> const& ptr, Args... buffer_arguments);

  RefCountReleaser close_output_device() override;

 private:
  // Called by the second output above.
  void set_link_output(LinkBuffer* link_buffer)
  {
    m_obuffer = static_cast<OutputBuffer*>(link_buffer->as_Buf2Dev());
  }

 protected:
  // Event: fd is writable.
  //
  // This default implementation writes data from the buffer to the fd until
  // 1) the buffer is empty, or
  // 2) write(2) wrote less than the number of bytes passed to it, or
  // 3) write(2) returned an error other than EAGAIN or EINTR, or
  // 4) EAGAIN != EWOULDBLOCK and EAGAIN happens twice in a row, or
  // 5) write(2) returned EINTR caused by SIGPIPE.
  // When write(2) returns an error other then EINTR (or when EINTR was caused by SIGPIPE),
  // EAGAIN or EWOULDBLOCK it calls the virtual function write_error, see below.
  virtual void write_to_fd(int fd);

  // This default implementation `close's the object (which removes it).
  virtual void write_error(int UNUSED_ARG(err)) { close(); }

  // Called from the streambuf associated with this device when pubsync() is called on it.
  friend class Buf2Dev;
  virtual int sync();
};

} // namespace evio

#include "OutputStream.h"
#include "InputDevice.h"

namespace evio {

template<typename... Args>
void OutputDevice::output(OutputDevicePtr& output_device_ptr, Args... output_buffer_arguments)
{
  Dout(dc::evio, "OutputDevice::output(" << (void*)&output_device_ptr << ", ...) [" << this << ']');
  m_output_device_ptr = &output_device_ptr;
  m_obuffer = m_output_device_ptr->create_buffer(this, output_buffer_arguments...);
}

template<typename INPUT_DEVICE, typename... Args>
void OutputDevice::output(boost::intrusive_ptr<INPUT_DEVICE> const& ptr, Args... buffer_arguments)
{
  Dout(dc::evio, "OutputDevice::output([" << &*ptr << "]) [" << this << ']');

  // We need to create a link buffer and use it to link the following two devices.
  InputDevice* input_device = ptr.get();
  OutputDevice* output_device = this;

  // Create the link buffer.
  LinkBufferPlus* link_buffer = new LinkBufferPlus(input_device, output_device, buffer_arguments...);

  // Initialize the output device to read from the link buffer.
  output_device->set_link_output(link_buffer);

  // Initialize the input device to write to the link buffer.
  input_device->set_link_input(link_buffer);
}

} // namespace evio