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

// OutputDevice must be included first.
#include "OutputDevice.h"

#ifndef EVIO_INPUT_DEVICE_H
#define EVIO_INPUT_DEVICE_H

#include "FileDescriptor.h"
#include "EventLoopThread.h"
#include "StreamBuf.h"
#include "utils/VTPtr.h"

namespace evio {

class InputDecoder;
class InputBuffer;
class LinkBufferPlus;
class InputDeviceEventsHandler;

class InputDevice : public virtual FileDescriptor
{
 public:
  struct VT_type
  {
    void* _input_user_data;     // Only use this after cloning a virtual table.
    void (*_read_from_fd)(InputDevice* self, int fd);
    RefCountReleaser (*_read_returned_zero)(InputDevice* self);
    RefCountReleaser (*_read_error)(InputDevice* self, int err);
    RefCountReleaser (*_data_received)(InputDevice* self, char const* new_data, size_t rlen);
  };

  struct VT_impl
  {
    // Event: 'fd' is readable.
    //
    // This default implementation reads data from the fd into the buffer until
    // 1) read(2) reads less than the available buffer space, or
    // 2) read(2) returns 0.
    // 3) The buffer is full and max_alloc was reached.
    // When the buffer is full stop_input_device is called.
    // When read(2) returns 0 the virtual function read_returned_zero is called, this MUST call stop_input_device()!
    // When read(2) returns an error other then EINTR (or when EINTR was caused by SIGPIPE), EAGAIN or EWOULDBLOCK
    // it calls the virtual function read_error, see below.
    static void read_from_fd(InputDevice* self, int fd);

    // The default behaviour is to close() the filedescriptor.
    static RefCountReleaser read_returned_zero(InputDevice* self) { return self->close_input_device(); }        // Read thread.

    // The default behaviour is to close() the filedescriptor.
    static RefCountReleaser read_error(InputDevice* self, int UNUSED_ARG(err)) { return self->close(); }        // Read thread.

    // The default behavior is to do nothing.
    static RefCountReleaser data_received(InputDevice* self, char const* new_data, size_t rlen);

    // Virtual table of InputDevice.
    static constexpr VT_type VT{
      /*InputDevice*/
      nullptr,
      read_from_fd,
      read_returned_zero,
      read_error,
      data_received
    };
  };

  // Make a deep copy of VT_ptr.
  virtual VT_type* clone_VT() { return VT_ptr.clone(this); }

  utils::VTPtr<InputDevice> VT_ptr;

 private:
  //---------------------------------------------------------------------------
  // Inferface with libev.
  //

  ev_io m_input_watcher;                // The watcher.
  using disable_release_t = aithreadsafe::Wrapper<RefCountReleaser, aithreadsafe::policy::Primitive<std::mutex>>;
  disable_release_t m_disable_release;

 protected:
  //---------------------------------------------------------------------------
  // The input buffer
  //

  InputDeviceEventsHandler* m_input_device_events_handler;      // The object that this device writes to.
  InputBuffer* m_ibuffer;                                       // A pointer to the input buffer.

 protected:
  friend class InputDeviceEventsHandler;
  void start_input_device(GetThread);
  RefCountReleaser stop_input_device();
  void disable_input_device();
  void enable_input_device(GetThread type);
  int get_input_fd() const override;

 protected:
  // Constructor.
  InputDevice();

  // Destructor.
  ~InputDevice();

  // Disallow copy constructing.
  InputDevice(InputDevice const&) = delete;

 public:
  //---------------------------------------------------------------------------
  // Public accessors:
  //

#if 0
  // Supposed to be used for passing it to other device constructors.
  Dev2Buf* rddbbuf() const { return m_ibuffer; }
#endif

  // Returns true if our watcher is linked in with libev.
  template<typename ThreadType>
  utils::FuzzyBool is_active(ThreadType type) const { return EventLoopThread::instance().is_active_input_device(m_input_watcher, type); }

 public:
  //---------------------------------------------------------------------------
  // Public manipulators:
  //

  template<typename... Args>
  void input(InputDecoder& input_decoder, Args... input_buffer_arguments);

  RefCountReleaser close_input_device() override;

 private:
  // This function is called by OutputDevice::output(boost::intrusive_ptr<INPUT_DEVICE> const&, ...).
  inline void set_link_input(LinkBufferPlus* link_buffer);
  // Give access to the above function.
  template<typename INPUT_DEVICE, typename... Args>
  friend void OutputDevice::output(boost::intrusive_ptr<INPUT_DEVICE> const& ptr, Args... buffer_arguments);

  // Override base class member function.
  void init_input_device(int fd) override;

  // The callback used by libev.
  static void s_evio_cb(ev_io* w, int)
  {
    // Release the mutex on 'loop' while calling an external function.
    auto release_lock = EventLoopThread::temporary_release();
    static_cast<InputDevice*>(w->data)->read_from_fd(w->fd);            // This might delete both, 'w' and 'w->data'.
  }

 protected:
  void read_from_fd(int fd) { VT_ptr->_read_from_fd(this, fd); }
  RefCountReleaser read_returned_zero() { return VT_ptr->_read_returned_zero(this); }
  RefCountReleaser read_error(int err) { return VT_ptr->_read_error(this, err); }
  RefCountReleaser data_received(char const* new_data, size_t rlen) { return VT_ptr->_data_received(this, new_data, rlen); }
};

} // namespace evio

#include "InputDecoder.h"

namespace evio {

template<typename... Args>
void InputDevice::input(InputDecoder& input_decoder, Args... input_buffer_arguments)
{
  Dout(dc::evio, "InputDevice::input(" << (void*)&input_decoder << ", ...) [" << this << ']');
  m_ibuffer = static_cast<InputDeviceEventsHandler&>(input_decoder).create_buffer(this, input_buffer_arguments...);
  m_input_device_events_handler = &input_decoder;
}

// Device-device link declarations.

// A LinkBufferPlus plays the role of link buffer, InputDeviceEventsHandler and OutputDevicePtr all at once.
class LinkBufferPlus : public LinkBuffer, public InputDeviceEventsHandler, public OutputDevicePtr
{
 public:
  LinkBufferPlus(InputDevice* input_device, OutputDevice* output_device, size_t minimum_blocksize, size_t buffer_full_watermark, size_t max_alloc) :
    LinkBuffer(input_device, output_device, minimum_blocksize, buffer_full_watermark, max_alloc) { m_input_device = input_device; m_output_device = output_device; }

 protected:
  size_t end_of_msg_finder(char const* new_data, size_t rlen) override;
};

void InputDevice::set_link_input(LinkBufferPlus* link_buffer)
{
  // You can't pass an InputDevice to a OutputDevice::output() when the InputDevice
  // already has a buffer (ie, you called already InputDevice::input()).
  //
  // If you *really* need to do this then it is possible to replace the buffer by
  // deriving from InputDevice (so you get access to the protected m_ibuffer) and
  // then calling from the derived intput device:
  //     if (m_ibuffer->release(CWDEBUG_ONLY(this)))
  //       m_ibuffer = nullptr;
  // before passing it to OutputDevice::output().
  //
  ASSERT(!m_ibuffer);
  m_ibuffer = static_cast<InputBuffer*>(static_cast<Dev2Buf*>(link_buffer));
  m_input_device_events_handler = link_buffer;
}

} // namespace evio

#endif // EVIO_INPUT_DEVICE_H
