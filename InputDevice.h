/**
 * evio -- A cwm4 git submodule for adding support for buffered, iostream oriented, epoll based I/O.
 *
 * @file
 * @brief Declaration of class InputDevice.
 *
 * @Copyright (C) 2018  Carlo Wood.
 *
 * RSA-1024 0x624ACAD5 1997-01-26                    Sign & Encrypt
 * Fingerprint16 = 32 EC A7 B6 AC DB 65 A6  F6 F6 55 DD 1C DC FF 61
 *
 * This file is part of evio.
 *
 * Evio is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Evio is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with evio.  If not, see <http://www.gnu.org/licenses/>.
 */

// OutputDevice must be included first.
#include "OutputDevice.h"

#ifndef EVIO_INPUT_DEVICE_H
#define EVIO_INPUT_DEVICE_H

#include "FileDescriptor.h"
#include "StreamBuf.h"

namespace evio {

class InputBuffer;
class LinkBufferPlus;
class Sink;

namespace protocol {
class Decoder;
} // namespace protocol

class InputDevice : public virtual FileDescriptor
{
 public:
  // Event: 'fd' is readable.
  //
  // This default implementation reads data from the fd into the buffer until
  // 1) is_stream_oriented() returns true and read(2) reads less than the available buffer space, or
  // 2) is_stream_oriented() returns false and read(2) returns EAGAIN.
  // 3) read(2) returns 0.
  // 4) The buffer is full and max_alloc was reached.
  // When the buffer is full stop_input_device is called.
  // When read(2) returns 0 the virtual function read_returned_zero is called, this MUST call stop_input_device()!
  // When read(2) returns an error other then EINTR (or when EINTR was caused by SIGPIPE, EAGAIN or EWOULDBLOCK)
  // it calls the virtual function read_error, see below.
  void read_from_fd(int& allow_deletion_count, int fd) override;
  virtual bool is_stream_oriented() { return true; }

  // The default behaviour is to close() the filedescriptor.
  virtual void read_returned_zero(int& allow_deletion_count) { close_input_device(allow_deletion_count); }

  // The default behaviour is to close() the filedescriptor.
  virtual void read_error        (int& allow_deletion_count, int UNUSED_ARG(err)) { close(allow_deletion_count); }

  // The default behavior is to do nothing.
  virtual void data_received     (int& allow_deletion_count, char const* new_data, size_t rlen);

 protected:
  //---------------------------------------------------------------------------
  // The input buffer
  //

  Sink* m_sink;                                         // The sink object that this device writes to.
  InputBuffer* m_ibuffer;                               // A pointer to the input buffer.
#ifdef DEBUGDEVICESTATS
  size_t m_received_bytes;
#endif

 protected:
  friend class Sink;
  bool start_input_device(state_t::wat const& state_w, utils::FuzzyCondition const& condition);
  void start_input_device(state_t::wat const& state_w);
  bool stop_input_device(state_t::wat const& state_w, utils::FuzzyCondition const& condition);
  void stop_input_device(state_t::wat const& state_w);
  bool disable_input_device(state_t::wat const& state_w, utils::FuzzyCondition const& condition);
  void disable_input_device(state_t::wat const& state_w);
  void enable_input_device();
  void remove_input_device(int& allow_deletion_count, state_t::wat const& state_w);

  [[gnu::always_inline]] void stop_input_device() { stop_input_device(state_t::wat(m_state)); }
  [[gnu::always_inline]] void disable_input_device() { disable_input_device(state_t::wat(m_state)); }
  [[gnu::always_inline]] void remove_input_device(int& allow_deletion_count) { remove_input_device(allow_deletion_count, state_t::wat(m_state)); }
 public: // ONLY public because StreamBuf::do_restart_input_device_if_needed() needs to call this :/
  [[gnu::always_inline]] void start_input_device() { start_input_device(state_t::wat(m_state)); }

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
  void set_protocol_decoder(Sink& decoder, Args... input_create_buffer_arguments);

  void close_input_device(int& allow_deletion_count) override final;

  RefCountReleaser close_input_device()
  {
    int allow_deletion_count = 0;
    close_input_device(allow_deletion_count);
    return {this, allow_deletion_count};
  }

 private:
  // This function is called by OutputDevice::set_source(boost::intrusive_ptr<INPUT_DEVICE> const&, ...).
  inline void set_sink(LinkBufferPlus* link_buffer);
  // This function is called by Sink::switch_protocol_decoder. Never call it from anywhere else.
  void switch_protocol_decoder(Sink& new_decoder) { m_sink = &new_decoder; }
  // Give access to the above function.
  template<typename INPUT_DEVICE>
  friend void OutputDevice::set_source(boost::intrusive_ptr<INPUT_DEVICE> const& ptr, size_t requested_minimum_block_size, size_t buffer_full_watermark, size_t max_alloc);

  // Override base class virtual functions.
  void init_input_device(state_t::wat const& state_w) override;
};

} // namespace evio

#include "protocol/Decoder.h"
#include "protocol/DecoderStream.h"

namespace evio {

template<typename... Args>
void InputDevice::set_protocol_decoder(Sink& decoder, Args... input_create_buffer_arguments)
{
#ifdef CWDEBUG
  LibcwDoutScopeBegin(LIBCWD_DEBUGCHANNELS, ::libcwd::libcw_do, dc::evio)
  LibcwDoutStream << "Entering InputDevice::set_protocol_decoder<";
  LibcwDoutStream << join(", ", libcwd::type_info_of<Args>().demangled_name()...) << ">(" <<
    (void*)&decoder << join_more(", ", input_create_buffer_arguments...) << ") [" << this << ']';
  LibcwDoutScopeEnd;
  NAMESPACE_DEBUG::Indent __cwds_debug_indent(DEBUGCHANNELS::dc::evio.is_on() ? 2 : 0);
#endif
  // Only call set_protocol_decoder once.
  // Use Decoder::switch_protocol_decoder from the decode() of the current decoder to change protocol decoder.
  ASSERT(!m_ibuffer);
  // The cast is needed to make use of the friend declaration in Sink.
  m_ibuffer = decoder.create_buffer(this, input_create_buffer_arguments...);
  m_sink = &decoder;
}

// Device-device link declarations.

//                     _ Source
//                    /  ::m_output_device ->
//        vvvvvvvvvvvvvvvvvvvvvvvvvvvvvv
// fd ==> InputDevice ==> LinkBufferPlus ==> OutputDevice ==> fd.
//                        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
//                         \__ Sink
//                    <------- ::m_input_device
//
// A LinkBufferPlus plays the role of link buffer, Sink and Source all at once.
//
class LinkBufferPlus : public LinkBuffer, public Sink, public Source
{
 public:
  LinkBufferPlus(InputDevice* input_device, OutputDevice* output_device, size_t minimum_block_size, size_t buffer_full_watermark, size_t max_alloc) :
    LinkBuffer(input_device, output_device, minimum_block_size, buffer_full_watermark, max_alloc) { m_input_device = input_device; m_output_device = output_device; }

 protected:
  // Must return 0 --> this is a Sink.
  std::streamsize end_of_msg_finder(char const* new_data, size_t rlen) override;
};

void InputDevice::set_sink(LinkBufferPlus* link_buffer)
{
  // You can't pass an InputDevice to a OutputDevice::set_source() when the InputDevice
  // already has a buffer (ie, you called already InputDevice::set_protocol_decoder(Decoder&, ...)).
  //
  // If you *really* need to do this then it is possible to replace the buffer by
  // deriving from InputDevice (so you get access to the protected m_ibuffer) and
  // then calling from the derived input device:
  //     if (m_ibuffer->release(CWDEBUG_ONLY(this)))
  //       m_ibuffer = nullptr;
  // before passing it to OutputDevice::set_source().
  //
  ASSERT(!m_ibuffer);
  m_ibuffer = static_cast<InputBuffer*>(static_cast<Dev2Buf*>(link_buffer));
  m_sink = link_buffer;
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
