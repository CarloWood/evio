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

namespace evio {

static constexpr size_t default_input_blocksize_c = 512;

class InputDecoder
{
 private:
  InputDevice* m_input_device;

 protected:
  // These may be called from decode().
  void start_input_device() { m_input_device->start_input_device(); }
  RefCountReleaser stop_input_device() { return m_input_device->stop_input_device(); }

 protected:
  friend class InputDevice;

  InputBuffer* create_buffer(
      InputDevice* input_device,
      size_t minimum_blocksize = default_input_blocksize_c,
      size_t buffer_full_watermark = std::numeric_limits<size_t>::max(),
      size_t max_alloc = std::numeric_limits<size_t>::max()
      )
  {
    m_input_device = input_device;
    InputBuffer* input_buffer = new InputBuffer(input_device, minimum_blocksize, buffer_full_watermark, max_alloc);
    return input_buffer;
  }

  // Returns the size of the first message, or 0 if there is no complete message.
  virtual size_t end_of_msg_finder(char const* new_data, size_t rlen)
  {
    char const* newline = static_cast<char const*>(std::memchr(new_data, '\n', rlen));
    return newline ? newline - new_data + 1 : 0;
  }

  virtual RefCountReleaser decode(MsgBlock msg) = 0;
};

} // namespace evio

#endif // EVIO_INPUT_DECODER_H
