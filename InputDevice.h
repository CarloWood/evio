// evio -- Event Driven I/O support.
//
//! @file
//! @brief Declaration of class InputDevice.
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

namespace evio {

class InputDecoder;
class InputBuffer;

class InputDevice : public virtual FileDescriptor
{
 private:
  //---------------------------------------------------------------------------
  // Inferface with libev.
  //

  ev_io m_input_watcher;                // The watcher.
  RefCountReleaser m_disable_release;

 protected:
  //---------------------------------------------------------------------------
  // The input buffer
  //

  InputDecoder* m_input_decoder;        // The object that this device writes to.
  InputBuffer* m_ibuffer;               // A pointer to the input buffer.

 protected:
  friend class InputDecoder;
  void start_input_device();
  RefCountReleaser stop_input_device();
  void disable_input_device();
  void enable_input_device();
  int get_input_fd() const;

 protected:
  // Constructor.
  InputDevice();

  // Destructor.
  ~InputDevice();

  // Disallow copy constructing.
  InputDevice(InputDevice const&) = delete;

#if CWDEBUG
  friend std::ostream& operator<<(std::ostream& os, InputDevice const* idptr)
  {
    return os << static_cast<void const*>(static_cast<FileDescriptor const*>(idptr));
  }
#endif

 public:
  //---------------------------------------------------------------------------
  // Public accessors:
  //

#if 0
  // Supposed to be used for passing it to other device constructors.
  Dev2Buf* rddbbuf() const { return m_ibuffer; }
#endif

  // Returns true if our watcher is linked in with libev.
  bool is_active() const { return ev_is_active(&m_input_watcher); }

 public:
  //---------------------------------------------------------------------------
  // Public manipulators:
  //

  template<typename... Args>
  void input(InputDecoder& input_decoder, Args... input_buffer_arguments);

  RefCountReleaser close_input_device() override;

 private:
  // Override base class member function.
  void init_input_device(int fd) override;

  // The callback used by libev.
  static void s_evio_cb(EV_P_ ev_io* w, int)
  {
    // Release the mutex on 'loop' while calling an external function.
    auto release_lock = EventLoopThread::temporary_release(EV_A);
    static_cast<InputDevice*>(w->data)->read_from_fd(w->fd);
  }

 protected:
  // Event: 'fd' is readable.
  //
  // This default implementation reads data from the fd into the buffer until
  // 1) read(2) reads less than the available buffer space, or
  // 2) read(2) returns 0.
  // 3) The buffer is full and max_alloc was reached.
  // When the buffer is full or when read(2) returns 0, stop_input_device is called.
  // When read(2) returns 0 then (after calling stop_input_device) the virtual function
  // read_returned_zero is called.
  // When read(2) returns an error other then EINTR (or when EINTR was caused by SIGPIPE),
  // EAGAIN or EWOULDBLOCK it calls the virtual function read_error, see below.
  virtual void read_from_fd(int fd);

  // The default behaviour is to close() the filedescriptor.
  virtual RefCountReleaser read_returned_zero() { return close_input_device(); }        // Read thread.

  // The default behaviour is to close() the filedescriptor.
  virtual RefCountReleaser read_error(int UNUSED_ARG(err)) { return close(); }          // Read thread.

  // The default behavior is to do nothing.
  virtual void data_received(char const* new_data, size_t rlen);
};

} // namespace evio

#include "InputDecoder.h"

namespace evio {

template<typename... Args>
void InputDevice::input(InputDecoder& input_decoder, Args... input_buffer_arguments)
{
  Dout(dc::evio, "InputDevice::input(" << (void*)&input_decoder << ", ...) [" << this << ']');
  m_input_decoder = &input_decoder;
  m_ibuffer = m_input_decoder->create_buffer(this, input_buffer_arguments...);
}

} // namespace evio
