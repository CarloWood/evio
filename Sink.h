// evio -- Event Driven I/O support.
//
//! @file
//! @brief Declaration of class Sink.
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

// InputDevice should be included first.
#include "InputDevice.h"

#ifndef EVIO_SINK_H
#define EVIO_SINK_H

#include "Protocol.h"
#include <limits>

namespace evio {

// Protocol
//  |
//  v                  ::set_sink()
// Sink <============= InputDevice <=== fd
// ::m_input_device ->
//  |
//  v
// InputDecoder (defines decode())
//
// The size of the input buffer is derived from the (average) message size as hinted by the Protocol.
//
// This class is used as the base class of InputDecoder or LinkBufferPlus. Any class that is not (an)
// InputDecoder that derives from this class must define a end_of_msg_finder that returns 0.
// Only InputDecoder::end_of_msg_finder is allowed to return a non-zero value, in that case the
// Sink is static_cast-ed to InputDecoder and decode() is called on the new message.

class Sink : public Protocol
{
 protected:
  InputDevice* m_input_device;

  void start_input_device() { m_input_device->start_input_device(FileDescriptor::state_t::wat(m_input_device->m_state)); }
  void stop_input_device() { m_input_device->stop_input_device(FileDescriptor::state_t::wat(m_input_device->m_state)); }
  void close_input_device(int& allow_deletion_count) { m_input_device->close_input_device(allow_deletion_count); }

  friend class InputDevice;
  InputBuffer* create_buffer(InputDevice* input_device)
      { return create_buffer(input_device,
                             /*buffer_full_watermark*/ 8 * StreamBuf::round_up_minimum_block_size(minimum_block_size()),
                             /*max_alloc*/ std::numeric_limits<size_t>::max()); }
  InputBuffer* create_buffer(InputDevice* input_device, size_t buffer_full_watermark)
      { return create_buffer(input_device,
                             buffer_full_watermark,
                             /*max_alloc*/ std::numeric_limits<size_t>::max()); }
  virtual InputBuffer* create_buffer(InputDevice*, size_t, size_t)
      { /*This should never be used*/ ASSERT(false); return nullptr; }

  // Returns the size of the first message (including end of msg sequence), or 0 if there is no complete message.
  virtual size_t end_of_msg_finder(char const* new_data, size_t rlen) = 0;
};

} // namespace evio

#endif // EVIO_SINK_H
