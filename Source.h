/**
 * evio -- A cwm4 git submodule for adding support for buffered, iostream oriented, epoll based I/O.
 *
 * @file
 * @brief Declaration of class Source.
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

#ifndef EVIO_SOURCE_H
#define EVIO_SOURCE_H

#include "StreamBuf.h"
#include "Protocol.h"
#include "RefCountReleaser.h"
#include <limits>

namespace evio {

class OutputDevice;
class InputDevice;

// Protocol
//   |
//   v                  ::set_source()
// Source ============> OutputDevice ==> fd
// ::m_output_device ->
//
// The size of the output buffer is derived from the (average) message size as hinted by the Protocol.
class Source : public Protocol
{
 protected:
  OutputDevice* m_output_device;

  void start_output_device();

  // Called for linked devices when the linked input device was closed.
  friend class InputDevice;
  [[gnu::always_inline]] inline RefCountReleaser flush_output_device();

  friend class OutputDevice;
  OutputBuffer* create_buffer(OutputDevice* output_device)
      { return create_buffer(output_device, 8 * StreamBuf::round_up_minimum_block_size(minimum_block_size()), std::numeric_limits<size_t>::max()); }
  OutputBuffer* create_buffer(OutputDevice* output_device, size_t buffer_full_watermark)
      { return create_buffer(output_device, buffer_full_watermark, std::numeric_limits<size_t>::max()); }
  virtual OutputBuffer* create_buffer(OutputDevice*, size_t, size_t)
      {
        // Derive from Source and override this function.
        ASSERT(false);
        return nullptr;
      }
};

} // namespace evio

#include "OutputDevice.h"

namespace evio {

RefCountReleaser Source::flush_output_device() { return m_output_device->flush_output_device(); }

} // namespace evio

#endif // EVIO_SOURCE_H
