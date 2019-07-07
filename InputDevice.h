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
    NAD_DECL((*_read_from_fd), InputDevice* self, int fd);
    NAD_DECL((*_hup), InputDevice* self, int fd);
    NAD_DECL((*_exceptional), InputDevice* self, int fd);
    NAD_DECL((*_read_returned_zero), InputDevice* self);
    NAD_DECL((*_read_error), InputDevice* self, int err);
    NAD_DECL((*_data_received), InputDevice* self, char const* new_data, size_t rlen);
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
    static NAD_DECL(read_from_fd, InputDevice* self, int fd);

    // Stream socket peer closed connection, or shut down writing half of connection.
    static NAD_DECL(hup, InputDevice* self, int fd);

    // There is some exceptional condition on the file descriptor. For example out-of-band data on a TCP socket.
    static NAD_DECL(exceptional, InputDevice* self, int fd);

    // The default behaviour is to close() the filedescriptor.
    static NAD_DECL(read_returned_zero, InputDevice* self) { NAD_CALL(self->close_input_device); }        // Read thread.

    // The default behaviour is to close() the filedescriptor.
    static NAD_DECL(read_error, InputDevice* self, int UNUSED_ARG(err)) { return NAD_CALL(self->close); } // Read thread.

    // The default behavior is to do nothing.
    static NAD_DECL(data_received, InputDevice* self, char const* new_data, size_t rlen);

    // Virtual table of InputDevice.
    static constexpr VT_type VT{
      /*InputDevice*/
      nullptr,
      read_from_fd,
      hup,
      exceptional,
      read_returned_zero,
      read_error,
      data_received
    };
  };

  // Make a deep copy of VT_ptr.
  virtual VT_type* clone_VT() { return VT_ptr.clone(this); }

  utils::VTPtr<InputDevice> VT_ptr;

 private:
  using disable_release_t = aithreadsafe::Wrapper<int, aithreadsafe::policy::Primitive<std::mutex>>;
  disable_release_t m_disable_release;
#ifdef DEBUGDEVICESTATS
  size_t m_received_bytes;
#endif

 protected:
  //---------------------------------------------------------------------------
  // The input buffer
  //

  InputDeviceEventsHandler* m_input_device_events_handler;      // The object that this device writes to.
  InputBuffer* m_ibuffer;                                       // A pointer to the input buffer.

 protected:
  friend class InputDeviceEventsHandler;
  void start_input_device(state_t::wat const& state_w);
  void stop_input_device(state_t::wat const& state_w);
  NAD_DECL(remove_input_device, state_t::wat const& state_w);
  void disable_input_device();
  void enable_input_device();

  [[gnu::always_inline]] void start_input_device() { start_input_device(state_t::wat(m_state)); }
  [[gnu::always_inline]] void stop_input_device() { stop_input_device(state_t::wat(m_state)); }
  [[gnu::always_inline]] NAD_DECL(remove_input_device) { NAD_CALL(remove_input_device, state_t::wat(m_state)); }

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

#ifdef DEBUGDEVICESTATS
  size_t received_bytes() const { return m_received_bytes; }
#endif

  // Returns true if the input device is registered with epoll.
  template<typename ThreadType>
  utils::FuzzyBool is_active(ThreadType) const
  {
    constexpr bool get_thread = std::is_base_of<GetThread, ThreadType>::value;
    constexpr bool put_thread = std::is_base_of<PutThread, ThreadType>::value;
    static_assert(get_thread || put_thread || std::is_same<AnyThread, ThreadType>::value,
                  "May only be called with ThreadType is SingleThread, AnyThread, GetThread or PutThread.");

    bool is_active = state_t::crat(m_state)->m_flags.is_active_input_device();

    // Basically we need the following table to hold:
    //  Currently active  SingleThread    AnyThread       GetThread       PutThread
    //       yes          WasTrue         WasTrue         WasTrue         WasTrue
    //        no          False           WasFalse        False           WasFalse
    //
    return is_active ? fuzzy::WasTrue : (get_thread ? fuzzy::False : fuzzy::WasFalse);
  }

 public:
  //---------------------------------------------------------------------------
  // Public manipulators:
  //

  template<typename... Args>
  void set_sink(InputDecoder& input_decoder, Args... input_create_buffer_arguments);

  NAD_DECL(close_input_device) override final;

  NAD_DECL_PUBLIC(close_input_device)
  {
    NAD_PUBLIC_BEGIN;
    NAD_CALL_FROM_PUBLIC(close_input_device);
    NAD_PUBLIC_END;
  }

 private:
  // This function is called by OutputDevice::set_source(boost::intrusive_ptr<INPUT_DEVICE> const&, ...).
  inline void set_sink(LinkBufferPlus* link_buffer);
  // Give access to the above function.
  template<typename INPUT_DEVICE>
  friend void OutputDevice::set_source(boost::intrusive_ptr<INPUT_DEVICE> const& ptr, size_t minimum_block_size, size_t buffer_full_watermark, size_t max_alloc);

  // Override base class virtual functions.
  void init_input_device(state_t::wat const& state_w) override;
  NAD_DECL(read_event) override final { NAD_CALL(VT_ptr->_read_from_fd, this, m_fd); }
  NAD_DECL(hup_event) override { NAD_CALL(VT_ptr->_hup, this, m_fd); }
  NAD_DECL(exceptional_event) override { NAD_CALL(VT_ptr->_exceptional, this, m_fd); }

  // Events, called from VT_impl::read_from_fd.
  NAD_DECL(read_returned_zero) { NAD_CALL(VT_ptr->_read_returned_zero, this); }
  NAD_DECL(read_error, int err) { NAD_CALL(VT_ptr->_read_error, this, err); }
  NAD_DECL(data_received, char const* new_data, size_t rlen) { NAD_CALL(VT_ptr->_data_received, this, new_data, rlen); }
};

} // namespace evio

#include "InputDecoder.h"

namespace evio {

template<typename... Args>
void InputDevice::set_sink(InputDecoder& input_decoder, Args... input_create_buffer_arguments)
{
  Dout(dc::evio, "InputDevice::set_sink(" << (void*)&input_decoder << ", ...) [" << this << ']');
  m_ibuffer = static_cast<InputDeviceEventsHandler&>(input_decoder).create_buffer(this, input_create_buffer_arguments...);
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

void InputDevice::set_sink(LinkBufferPlus* link_buffer)
{
  // You can't pass an InputDevice to a OutputDevice::set_source() when the InputDevice
  // already has a buffer (ie, you called already InputDevice::set_sink(InputDecoder&, ...)).
  //
  // If you *really* need to do this then it is possible to replace the buffer by
  // deriving from InputDevice (so you get access to the protected m_ibuffer) and
  // then calling from the derived intput device:
  //     if (m_ibuffer->release(CWDEBUG_ONLY(this)))
  //       m_ibuffer = nullptr;
  // before passing it to OutputDevice::set_source().
  //
  ASSERT(!m_ibuffer);
  m_ibuffer = static_cast<InputBuffer*>(static_cast<Dev2Buf*>(link_buffer));
  m_input_device_events_handler = link_buffer;
}

// This can be thrown from read_returned_zero when you want read_from_fd to continue reading anyway.
// Currently only used by PersistentInputFile (all other devices actually reached the permanent end,
// so probably none of them will ever use this).
struct OneMoreByte
{
  char byte;
};

} // namespace evio

#endif // EVIO_INPUT_DEVICE_H
