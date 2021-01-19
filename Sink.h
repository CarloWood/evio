/**
 * evio -- A cwm4 git submodule for adding support for buffered, iostream oriented, epoll based I/O.
 *
 * @file
 * @brief Declaration of class Sink.
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

#include "protocol/MessageLengthInterface.h"
#include <limits>

#ifdef CWDEBUG
NAMESPACE_DEBUG_CHANNELS_START
extern channel_ct endofmsg;
extern channel_ct decoder;
NAMESPACE_DEBUG_CHANNELS_END
#endif

namespace evio {

class InputDevice;

enum sink_type {
  decoder_sink,
  decoder_stream_sink
};

struct EndOfMsgFinderResult
{
  sink_type m_sink_type;

  void reset()
  {
    m_sink_type = decoder_sink;
  }

  EndOfMsgFinderResult()
  {
    reset();
  }
};

// MessageLengthInterface
//  |
//  v                  ::set_sink()
// Sink <============= InputDevice <=== fd
// ::m_input_device ->
//  |
//  v
// Decoder (defines decode())
//
// The size of the input buffer is derived from the (average) message length as hinted by the Decoder.
//
// This class is used as the base class of Decoder or LinkBufferPlus. Any class that is not (a)
// Decoder that derives from this class MUST define a end_of_msg_finder that returns 0.
//
// Only (classes derived from) Decoder::end_of_msg_finder is allowed to return a non-zero value:
// in that case the Sink is static_cast-ed to Decoder and decode() is called on the new message.

class Sink : public protocol::MessageLengthInterface
{
 public:
  static constexpr size_t c_undefined = std::numeric_limits<size_t>::max();

 protected:
  InputDevice* m_input_device;
  std::function<int()> m_get_content_length;    // m_get_content_length() should return the total size of the input by the time end_of_msg_finder is called.
  size_t m_content_length;                      // Cached value of m_get_content_length(), or std::numeric_limits<size_t>::max() when not given.
  size_t m_total_len;                           // The total number of bytes that this decoder has received (by end_of_msg_finder).
  Sink* m_next_decoder;                         // The decoder to switch to after having received m_content_length bytes.

  // (Re)initialize the above member variables.
  void initialize(InputDevice* input_device);

  [[gnu::always_inline]] inline void start_input_device();
  [[gnu::always_inline]] inline void stop_input_device();
  [[gnu::always_inline]] inline void close_input_device(int& allow_deletion_count);

  friend class InputDevice;
  void initialize_content_length();
  InputBuffer* create_buffer(InputDevice* input_device)
      { return create_buffer(input_device,
                             /*buffer_full_watermark*/ 8 * StreamBuf::round_up_minimum_block_size(minimum_block_size()),
                             /*max_alloc*/ std::numeric_limits<size_t>::max()); }
  InputBuffer* create_buffer(InputDevice* input_device, size_t buffer_full_watermark)
      { return create_buffer(input_device,
                             buffer_full_watermark,
                             /*max_alloc*/ std::numeric_limits<size_t>::max()); }
  InputBuffer* create_buffer(InputDevice* input_device, size_t buffer_full_watermark, size_t max_alloc);

 protected:
  // decode is only called from InputDevice::data_received, which is both consumer
  // and producer thread of m_input_device->m_ibuffer; therefore this function,
  // which maybe only be called from decode() can call StreamBuf::reduce_buffer.
  [[gnu::always_inline]] inline void change_specs(size_t minimum_block_size, size_t buffer_full_watermark, size_t max_allocated_block_size) const;

  // These can be called from Decoder::decode().
  [[gnu::always_inline]] inline void switch_protocol_decoder(Sink& new_decoder,
                               size_t buffer_full_watermark,
                               size_t max_alloc = std::numeric_limits<size_t>::max());

  void switch_protocol_decoder(Sink& new_decoder)
  {
    switch_protocol_decoder(new_decoder, 8 * StreamBuf::round_up_minimum_block_size(new_decoder.minimum_block_size()), std::numeric_limits<size_t>::max());
  }

 public:
  // Switch to next_decoder after having received exactly get_content_length() bytes.
  void set_next_decoder(Sink& next_decoder, std::function<int()> get_content_length)
  {
    m_next_decoder = &next_decoder;
    m_get_content_length = get_content_length;
  }

  size_t decoder_rlen(size_t rlen) const
  {
    // Return the number of bytes of rlen that are still part of this decoders content.
    return std::min(m_total_len + rlen, m_content_length) - m_total_len;
  }

  // Returns the length (starting at new_data) up till and including the last end of msg sequence,
  // or 0 if there is no complete message. Note that in order to detect end of message sequences
  // that cross a boundary, internal state might be needed.
  //
  // Should only be called by InputDevice::data_received() or classes that override that.
  //
  // IMPORTANT: If an end_of_msg_finder is overridden for a class derived from DecoderStream then
  // one must do `result.m_sink_type = decoder_stream_sink` before returning from that function.
  virtual size_t end_of_msg_finder(char const* new_data, size_t rlen, EndOfMsgFinderResult& result) = 0;

  // This is called when content length bytes have been processed (so only when set_next_decoder was used).
  // The default does nothing.
  virtual void end_of_content(int& UNUSED_ARG(allow_deletion_count)) { }
};

} // namespace evio

#include "InputDevice.h"

namespace evio {

// decode needs access to these.
void Sink::start_input_device() { m_input_device->start_input_device(); }
void Sink::stop_input_device() { m_input_device->stop_input_device(); }
void Sink::close_input_device(int& allow_deletion_count) { m_input_device->close_input_device(allow_deletion_count); }

void Sink::change_specs(size_t minimum_block_size, size_t buffer_full_watermark, size_t max_allocated_block_size) const
{
  m_input_device->m_ibuffer->change_specs(minimum_block_size, buffer_full_watermark, max_allocated_block_size);
}

void Sink::switch_protocol_decoder(Sink& new_decoder, size_t buffer_full_watermark, size_t max_alloc)
{
  DoutEntering(dc::evio, "Sink::switch_protocol_decoder(new_decoder, " << buffer_full_watermark << ", " << max_alloc << ")");
  change_specs(new_decoder.minimum_block_size(), buffer_full_watermark, max_alloc);
  new_decoder.initialize(m_input_device);
  m_input_device->switch_protocol_decoder(new_decoder);
  m_input_device = nullptr;
  std::istream* istr = dynamic_cast<std::istream*>(&new_decoder);
  if (istr)
    istr->rdbuf(new_decoder.m_input_device->m_ibuffer);
}

} // namespace evio
