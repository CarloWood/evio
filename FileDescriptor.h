// evio -- Event Driven I/O support.
//
//! @file
//! @brief Declaration of namespace evio; class IOBase, InputDevice, OutputDevice, no_input_ct and no_output_ct.
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

#include "evio.h"
#include "dbstreambuf.h"
#include "utils/sbll.h"
#include "utils/AIRefCount.h"

class EventLoopThread;

namespace evio {

// Virtual base class for IO Devices.
//
// This class takes care of the life-time of an Input-, Output- or IO-Device.
class IOBase : public AIRefCount
{
 private:
  virtual void init_input_device(int) { }
  virtual void init_output_device(int) { }

 protected:
  virtual void start_input_device(EventLoopThread&) { }
  virtual void start_output_device(EventLoopThread&) { }
  virtual void stop_input_device() { }
  virtual void stop_output_device() { }

 protected:
#ifdef CWDEBUG
  ~IOBase() { Dout(dc::notice, "Destructing IOBase [" << (void*)this << "]"); }
#endif

 public:
  // (Re)Initialize the FileDescriptor.
  void init(int fd)
  {
    init_input_device(fd);
    init_output_device(fd);
  }

  void start(EventLoopThread& evio_loop)
  {
    start_input_device(evio_loop);
    start_output_device(evio_loop);
  }

  void stop()
  {
    stop_input_device();
    stop_output_device();
  }
};

class InputDevice : public virtual IOBase
{
 public:
  // The default blocksize for your `dbstreambuf_ct' input buffers, used
  // when you don't pass that size to the constructors.
  static size_t constexpr default_blocksize_c = 512;

 protected:
  //---------------------------------------------------------------------------
  // The input buffer
  //

  input_buffer_ct* m_ibuffer;   // A pointer to the input buffer.

 private:
  //---------------------------------------------------------------------------
  // Inferface with libev.
  //

  friend EventLoopThread;       // Needs access to m_input_watcher.
  ev_io m_input_watcher;        // The watcher.

  // Override base class member functions.
  void init_input_device(int fd) override;
 protected:
  void start_input_device(EventLoopThread& evio_loop) override;
  void stop_input_device() override;

 protected:
  //---------------------------------------------------------------------------
  // Constructor:
  //
  // Protected: May only be constructed by dbbuf_fd_dtct.
  //
  InputDevice(input_buffer_ct* ibuf) : m_ibuffer(ibuf)
  {
    // Give m_input_watcher known values; cause is_active() to return false.
    ev_io_init(&m_input_watcher, InputDevice::s_evio_cb, -1, EV_UNDEF);
    // Tell the input buffer that we are the linked input device.
    m_ibuffer->set_input_device(this);
  }

  // Destructor.
  ~InputDevice()
  {
    // Delete the input buffer if it is no longer needed.
    m_ibuffer->release(this);
  }

  // Disallow copy constructing.
  InputDevice(InputDevice const&) = delete;

 protected:
  // Event: 'fd' is readable.
  virtual void read_from_fd(int fd) = 0;

 private:
  // The call back used by libev.
  static void s_evio_cb(EV_P_ ev_io* w, int) { static_cast<InputDevice*>(w->data)->read_from_fd(w->fd); }

 public:
  //---------------------------------------------------------------------------
  // Public accessors:
  //

  // Supposed to be used for passing it to other device constructors.
  input_buffer_ct* rddbbuf(void) const { return m_ibuffer; }

  // Returns true if our watcher is linked in with libev.
  bool is_active() const { return ev_is_active(&m_input_watcher); }
};

class OutputDevice : public virtual IOBase
{
 public:
  // The default blocksize for your `dbstreambuf_ct' output buffers, used
  // when you don't pass that size to the constructors.
  static size_t constexpr default_blocksize_c = 2048;

 protected:
  //---------------------------------------------------------------------------
  // The output buffer
  //

  output_buffer_ct* m_obuffer;  // A pointer to the output buffer.

 private:
  //---------------------------------------------------------------------------
  // Inferface with libev.
  //

  friend EventLoopThread;       // Needs access to m_output_watcher.
  ev_io m_output_watcher;       // The watcher.

  // Override base class member functions.
  void init_output_device(int fd) override;
 protected:
  void start_output_device(EventLoopThread& evio_loop) override;
  void stop_output_device() override;

 protected:
  //---------------------------------------------------------------------------
  // Constructor:
  //
  // Protected: May only be constructed by dbbuf_fd_dtct.
  //
  OutputDevice(output_buffer_ct* obuf) : m_obuffer(obuf)
  {
    // Give m_output_watcher known values; cause is_active() to return false.
    ev_io_init(&m_output_watcher, OutputDevice::s_evio_cb, -1, EV_UNDEF);
    // Tell the input buffer that we are the linked input device.
    m_obuffer->set_output_device(this);
  }

  // Destructor.
  ~OutputDevice()
  {
    // Delete the output buffer if it is no longer needed.
    m_obuffer->release(this);
  }

  // Disallow copy constructing.
  OutputDevice(OutputDevice const&) = delete;

 protected:
  // Event: 'fd' is writable.
  virtual void write_to_fd(int fd) = 0;

 private:
  // The call back used by libev.
  static void s_evio_cb(EV_P_ ev_io* w, int) { static_cast<OutputDevice*>(w->data)->write_to_fd(w->fd); }

 public:
  //---------------------------------------------------------------------------
  // Public accessors:
  //

  // Supposed to be used for passing it to other device constructors.
  output_buffer_ct* rddbbuf(void) const { return m_obuffer; }

  // Returns true if our watcher is linked in with libev.
  bool is_active() const { return ev_is_active(&m_output_watcher); }
};

class no_input_ct : public InputDevice
{
 protected:
  no_input_ct(input_buffer_ct* ibuf) : InputDevice(ibuf) { }
  void read_from_fd(int) override { stop_input_device(); }
};

class no_output_ct : public OutputDevice
{
 protected:
  no_output_ct(output_buffer_ct* obuf) : OutputDevice(obuf) { }
  void write_to_fd(int) override
  {
    DoutFatal(dc::core, "Don't write data to \"no_output_ct\"");
  }
};

} // namespace evio
