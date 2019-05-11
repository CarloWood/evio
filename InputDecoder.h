// evio -- Event Driven I/O support.
//
//! @file
//! @brief Declaration of class InputDecoder.
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

#ifndef EVIO_INPUT_DECODER_H
#define EVIO_INPUT_DECODER_H

#include "StreamBuf.h"  // MsgBlock.
#include <limits>
#include <cstring>

namespace evio {

static constexpr size_t default_input_blocksize_c = 512 - sizeof(MemoryBlock) - CW_MALLOC_OVERHEAD;

// This class is used as the base class of InputDecoder or LinkBufferPlus.
// Any class that is not (an) InputDecoder that derives from this class
// must define a end_of_msg_finder that returns 0.
class InputDeviceEventsHandler
{
 protected:
  InputDevice* m_input_device;

  void start_input_device(GetThread type) { m_input_device->start_input_device(type); }
  RefCountReleaser stop_input_device() { return m_input_device->stop_input_device(); }

  friend class InputDevice;
  InputBuffer* create_buffer(InputDevice* input_device)
      { return create_buffer(input_device, default_input_blocksize_c, 8 * default_input_blocksize_c, std::numeric_limits<size_t>::max()); }
  InputBuffer* create_buffer(InputDevice* input_device, size_t minimum_blocksize)
      { return create_buffer(input_device, minimum_blocksize, 8 * minimum_blocksize, std::numeric_limits<size_t>::max()); }
  InputBuffer* create_buffer(InputDevice* input_device, size_t minimum_blocksize, size_t buffer_full_watermark)
      { return create_buffer(input_device, minimum_blocksize, buffer_full_watermark, std::numeric_limits<size_t>::max()); }
  virtual InputBuffer* create_buffer(InputDevice*, size_t, size_t, size_t)
      { /* Should never be used */ return nullptr; }

  // Returns the size of the first message (including end of msg sequence), or 0 if there is no complete message.
  // BRT.
  virtual size_t end_of_msg_finder(char const* new_data, size_t rlen) = 0;
};

class InputDecoder : public InputDeviceEventsHandler
{
 private:
  InputBuffer* create_buffer(
      InputDevice* input_device,
      size_t minimum_blocksize,
      size_t buffer_full_watermark,
      size_t max_alloc
      ) override
  {
    DoutEntering(dc::io, "InputDecoder::create_buffer(" << input_device << ", " << minimum_blocksize << ", " << buffer_full_watermark << ", " << max_alloc << ")");
    m_input_device = input_device;
    InputBuffer* input_buffer = new InputBuffer(input_device, minimum_blocksize, buffer_full_watermark, max_alloc);
    return input_buffer;
  }

 protected:
  // Given the char array new_data of size rlen, returns the length of the string (starting a new_data) up to and
  // including the first newline, char if any. Otherwise returns 0.
  // BRT.
  size_t end_of_msg_finder(char const* new_data, size_t rlen) override
  {
    DoutEntering(dc::io, "InputDecoder::end_of_msg_finder(..., " << rlen << ")");
    char const* newline = static_cast<char const*>(std::memchr(new_data, '\n', rlen));
    return newline ? newline - new_data + 1 : 0;
  }

  friend class InputDevice;
  virtual RefCountReleaser decode(MsgBlock&& msg, GetThread type) = 0;
};

} // namespace evio

#endif // EVIO_INPUT_DECODER_H
