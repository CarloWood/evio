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
#include "StreamBuf.h"
#include "utils/VTPtr.h"

namespace utils {
class FuzzyCondition;
} // namespace utils

namespace evio {

class OutputDevicePtr;
class OutputBuffer;

class OutputDevice : public virtual FileDescriptor
{
 public:
  struct VT_type
  {
    void* _output_user_data;    // Only use this after cloning a virtual table.
    void (*_write_to_fd)(OutputDevice*, int);
    void (*_write_error)(OutputDevice*, int);
  };

  struct VT_impl
  {
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
    static void write_to_fd(OutputDevice* self, int fd);

    // This default implementation `close's the object (which removes it).
    static void write_error(OutputDevice* self, int UNUSED_ARG(err)) { self->close(); }

    // Virtual table of OutputDevice.
    static constexpr VT_type VT{
      /*OutputDevice*/
      nullptr,
      write_to_fd,
      write_error
    };
  };

  // Make a deep copy of VT_ptr.
  virtual VT_type* clone_VT() { return VT_ptr.clone(this); }

  utils::VTPtr<OutputDevice> VT_ptr;

 private:
  //---------------------------------------------------------------------------
  // Inferface with libev.
  //

  //ev_io m_output_watcher;               // The watcher.
  using disable_release_t = aithreadsafe::Wrapper<RefCountReleaser, aithreadsafe::policy::Primitive<std::mutex>>;
  disable_release_t m_disable_release;

 protected:
  //---------------------------------------------------------------------------
  // The output buffer
  //

  OutputDevicePtr* m_output_device_ptr; // A pointer to an object that points back to us.
  OutputBuffer* m_obuffer;              // A pointer to the output buffer.

 protected:
  // The default condition just checks if the output device is not already active.
  // When that is used, you are responsible to not call start_output_device when
  // (in the current thread) the device is already active, also in the case of
  // races (aka, there are no possible races allowed). Passing PutThread here
  // should take care of that in most cases, think "only the put thread will start
  // an output device (automatically)". However, of course that means that either
  // the caller *is* the put thread, or you are certain the device is stopped and
  // no put thread is running -- aka nobody is writing to the device -- when this
  // function is being called.
  friend class OutputDevicePtr;
  void start_output_device(state_t::wat const& state_w, utils::FuzzyCondition const& condition);
  void start_output_device(state_t::wat const& state_w);
  RefCountReleaser stop_output_device();
  RefCountReleaser stop_output_device(utils::FuzzyCondition const& condition);
  [[gnu::always_inline]] inline void stop_output_device(state_t::wat const& state_w, utils::FuzzyCondition const& condition);
  [[gnu::always_inline]] inline void stop_output_device(state_t::wat const& state_w);

  RefCountReleaser remove_output_device(state_t::wat const& state_w);
  void disable_output_device();
  void enable_output_device();

  [[gnu::always_inline]] void start_output_device() { start_output_device(state_t::wat(m_state)); }
  [[gnu::always_inline]] RefCountReleaser remove_output_device() { return remove_output_device(state_t::wat(m_state)); }

 protected:
  OutputDevice();
  ~OutputDevice();

  // Disallow copy constructing.
  OutputDevice(OutputDevice const&) = delete;

 private:
  // Override base class member function.
  void init_output_device(state_t::wat const& state_w) override;

 public:
  //---------------------------------------------------------------------------
  // Public accessors:
  //

#if 0
  // Supposed to be used for passing it to other device constructors.
  Buf2Dev* rddbbuf() const { return m_obuffer; }
#endif

  // Returns true if the output device is registered with epoll.
  template<typename ThreadType>
  utils::FuzzyBool is_active(ThreadType) const
  {
    constexpr bool get_thread = std::is_base_of<GetThread, ThreadType>::value;
    constexpr bool put_thread = std::is_base_of<PutThread, ThreadType>::value;
    static_assert(get_thread || put_thread || std::is_same<AnyThread, ThreadType>::value,
                  "May only be called with ThreadType is SingleThread, AnyThread, GetThread or PutThread.");

    bool is_active = state_t::crat(m_state)->m_flags.is_active_output_device();

    // Basically we need the following table to hold:
    //  Currently active  SingleThread    AnyThread       GetThread       PutThread
    //       yes          WasTrue         WasTrue         WasTrue         WasTrue
    //        no          False           WasFalse        WasFalse        False
    //
    return is_active ? fuzzy::WasTrue : (put_thread ? fuzzy::False : fuzzy::WasFalse);
  }

  void restart_if_non_active()
  {
    // This function should be called only from Buf2Dev::flush and OutputDevice::enable_output_device, and therefore be an output device.
    state_t::wat state_w(m_state);
    ASSERT(state_w->m_flags.is_output_device());
    if (state_w->m_flags.is_writable() && !state_w->m_flags.is_active_output_device())
      start_output_device(state_w);
  }

 public:
  //---------------------------------------------------------------------------
  // Public manipulators:
  //

  template<typename... Args>
  void output(OutputDevicePtr& output_device_ptr, Args... output_buffer_arguments);

  template<typename DEVICE, typename... Args>
  void output(boost::intrusive_ptr<DEVICE> const& ptr, Args... buffer_arguments);

  RefCountReleaser flush_output_device();
  RefCountReleaser close_output_device() override;

 private:
  // Called by the second output above.
  void set_link_output(LinkBuffer* link_buffer)
  {
    m_obuffer = static_cast<OutputBuffer*>(link_buffer->as_Buf2Dev());
  }

 protected:
  void write_event() override { VT_ptr->_write_to_fd(this, m_fd); }
  void write_error(int err) { VT_ptr->_write_error(this, err); }

  // Called from the streambuf associated with this device when pubsync() is called on it.
  friend class StreamBufProducer;
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
