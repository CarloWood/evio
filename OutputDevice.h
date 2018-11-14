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

class OutputStream;
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

  OutputStream* m_output_stream;        // The object that this device reads from.
  OutputBuffer* m_obuffer;              // A pointer to the output buffer.

 protected:
  void start_output_device();
  RefCountReleaser stop_output_device();
  void disable_output_device();
  void enable_output_device();
  int get_output_fd() const;

 protected:
#if CWDEBUG
  friend std::ostream& operator<<(std::ostream& os, OutputDevice const* odptr)
  {
    return os << static_cast<void const*>(static_cast<FileDescriptor const*>(odptr));
  }
#endif

  OutputDevice() : m_output_stream(nullptr), m_obuffer(nullptr)
  {
    DoutEntering(dc::evio, "OutputDevice::OutputDevice() [" << this << ']');
    // Mark that OutputDevice is a derived class.
    m_flags |= FDS_W;
    // Give m_output_watcher known values; cause is_active() to return false.
    ev_io_init(&m_output_watcher, OutputDevice::s_evio_cb, -1, EV_UNDEF);
  }

  // Destructor.
  ~OutputDevice()
  {
    DoutEntering(dc::evio, "OutputDevice::~OutputDevice() [" << this << ']');
    // Don't delete a device? At most close() it and delete all boost::intrusive_ptr's to it.
    ASSERT(!is_active());
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
  void output(OutputStream& output_stream, Args... output_buffer_arguments);

  RefCountReleaser close_output_device() override;

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

namespace evio {

template<typename... Args>
void OutputDevice::output(OutputStream& output_stream, Args... output_buffer_arguments)
{
  Dout(dc::evio, "OutputDevice::output(" << (void*)&output_stream << ", ...) [" << this << ']');
  m_output_stream = &output_stream;
  m_obuffer = m_output_stream->create_buffer(this, output_buffer_arguments...);
}

} // namespace evio
