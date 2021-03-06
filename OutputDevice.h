/**
 * evio -- A cwm4 git submodule for adding support for buffered, iostream oriented, epoll based I/O.
 *
 * @file
 * @brief Declaration of class OutputDevice.
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

#pragma once

#include "RawOutputDevice.h"
#include "StreamBuf.h"
#include "Protocol.h"

namespace evio {

class Source;
class OutputBuffer;
class LinkBufferPlus;

class OutputDevice : public RawOutputDevice
{
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
  void write_to_fd(int& allow_deletion_count, int fd) override;

  void close_output_device(int& allow_deletion_count) override final;

 protected:
  //---------------------------------------------------------------------------
  // The output buffer
  //

#if defined(__clang__) && __clang_major__ <= 6
  // clang++ 6.x and lower erroneously assumes that this class is always aligned like RawOutputDevice (64),
  // but that is not true when this class is used in multiple inheritance. So, force the alignment that
  // clang++ assumes.
  alignas(16)
#endif
  Source* m_source;                     // A pointer to the source object that creates the output buffer for us (has knowledge of the Protocol).
  OutputBuffer* m_obuffer;              // A pointer to the output buffer.
  bool m_is_link_buffer;                // True if m_obuffer is a LinkBufferPlus*.
#ifdef DEBUGDEVICESTATS
  size_t m_sent_bytes;
#endif

 protected:
  OutputDevice();
  ~OutputDevice();

  // Disallow copy constructing.
  OutputDevice(OutputDevice const&) = delete;

 protected:
  // Called from the streambuf associated with this device when pubsync() is called on it.
  friend class StreamBufProducer;
  virtual int sync();

  // This default implementation `close's the object (which removes it).
  virtual void write_error(int& allow_deletion_count, int UNUSED_ARG(err)) { close(allow_deletion_count); }

 public:
  //---------------------------------------------------------------------------
  // Public accessors:
  //

#if 0
  // Supposed to be used for passing it to other device constructors.
  Buf2Dev* rddbbuf() const { return m_obuffer; }
#endif

#ifdef DEBUGDEVICESTATS
  size_t sent_bytes() const { return m_sent_bytes; }
#endif

 public:
  //---------------------------------------------------------------------------
  // Public manipulators:
  //

  template<typename... Args>
  void set_source(Source& output_device_ptr, Args... output_create_buffer_arguments);

  template<typename INPUT_DEVICE>
  void set_source(boost::intrusive_ptr<INPUT_DEVICE> const& ptr,
      size_t requested_minimum_block_size, size_t buffer_full_watermark, size_t max_alloc = std::numeric_limits<size_t>::max());

  template<typename INPUT_DEVICE>
  void set_source(boost::intrusive_ptr<INPUT_DEVICE> const& ptr,
      size_t requested_minimum_block_size)
  {
    set_source(ptr, requested_minimum_block_size, 8 * StreamBuf::round_up_minimum_block_size(requested_minimum_block_size));
  }

  using RawOutputDevice::close_output_device;

 private:
  // Called by the second set_source above.
  inline void set_source(LinkBufferPlus* link_buffer);

  // Override base class virtual functions.
#ifdef DEBUGDEVICESTATS
  void init_output_device(state_t::wat const& state_w) override;
#endif
};

} // namespace evio

#include "OutputStream.h"
#include "InputDevice.h"

namespace evio {

void OutputDevice::set_source(LinkBufferPlus* link_buffer)
{
  m_obuffer = static_cast<OutputBuffer*>(link_buffer->as_Buf2Dev());
  m_source = link_buffer;
  m_is_link_buffer = true;
}

template<typename... Args>
void OutputDevice::set_source(Source& output_device_ptr, Args... output_create_buffer_arguments)
{
#ifdef CWDEBUG
  LibcwDoutScopeBegin(LIBCWD_DEBUGCHANNELS, ::libcwd::libcw_do, dc::evio)
  LibcwDoutStream << "Entering OutputDevice::set_source<";
  LibcwDoutStream << join(", ", libcwd::type_info_of<Args>().demangled_name()...) << ">(" <<
    (void*)&output_device_ptr << join_more(", ", output_create_buffer_arguments...) << ") [" << this << ']';
  LibcwDoutScopeEnd;
  NAMESPACE_DEBUG::Indent __cwds_debug_indent(DEBUGCHANNELS::dc::evio.is_on() ? 2 : 0);
#endif
  m_source = &output_device_ptr;
  m_obuffer = m_source->create_buffer(this, output_create_buffer_arguments...);
  m_is_link_buffer = false;
}

template<typename INPUT_DEVICE>
void OutputDevice::set_source(boost::intrusive_ptr<INPUT_DEVICE> const& ptr, size_t requested_minimum_block_size, size_t buffer_full_watermark, size_t max_alloc)
{
  DoutEntering(dc::evio, "OutputDevice::set_source<" << type_info_of<INPUT_DEVICE>().demangled_name() << ">([" << &*ptr << "], " << requested_minimum_block_size << ", " << buffer_full_watermark << ", " << max_alloc << ") [" << this << ']');

  // We need to create a link buffer and use it to link the following two devices.
  InputDevice* input_device = ptr.get();
  OutputDevice* output_device = this;

  // Create the link buffer.
  LinkBufferPlus* link_buffer = new LinkBufferPlus(input_device, output_device, StreamBuf::round_up_minimum_block_size(requested_minimum_block_size), buffer_full_watermark, max_alloc);

  // Initialize the output device to read from the link buffer.
  output_device->set_source(link_buffer);

  // Initialize the input device to write to the link buffer.
  input_device->set_sink(link_buffer);
}

} // namespace evio
