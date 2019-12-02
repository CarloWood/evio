/**
 * evio -- A cwm4 git submodule for adding support for buffered, iostream oriented, epoll based I/O.
 *
 * @file
 * @brief Declaration of class InputDecoder.
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

// InputDevice should be included first.
#include "InputDevice.h"

#ifndef EVIO_INPUT_DECODER_H
#define EVIO_INPUT_DECODER_H

#include "StreamBuf.h"  // MsgBlock.
#include "Sink.h"
#include <cstring>

namespace evio {

class InputDecoder : public Sink
{
 private:
  InputBuffer* create_buffer(InputDevice* input_device, size_t buffer_full_watermark, size_t max_alloc) override;

 public: // Should only be called by InputDevice::data_received or classes that override that.
  // Given the char array new_data of size rlen, returns the length of the string (starting at new_data) up to and
  // including the first newline char, if any. Otherwise returns 0.
  size_t end_of_msg_finder(char const* new_data, size_t rlen) override;

  friend class InputDevice;
  virtual void decode(int& allow_deletion_count, MsgBlock&& msg) = 0;
};

} // namespace evio

#endif // EVIO_INPUT_DECODER_H
