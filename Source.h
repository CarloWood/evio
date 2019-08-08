// evio -- Event Driven I/O support.
//
//! @file
//! @brief Declaration of class Source.
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

// OutputDevice.h must be included first.
#include "OutputDevice.h"

#ifndef EVIO_SOURCE_H
#define EVIO_SOURCE_H

#include "StreamBuf.h"
#include "Protocol.h"
#include <limits>

namespace evio {

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

  void start_output_device()
  {
    DoutEntering(dc::evio, "Source::start_output_device() [" << m_output_device << ']');
    FileDescriptor::state_t::wat state_w(m_output_device->m_state);
    if (!state_w->m_flags.is_active_output_device())
      m_output_device->start_output_device(state_w);
  }

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

#endif // EVIO_SOURCE_H
