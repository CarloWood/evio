/**
 * evio -- A cwm4 git submodule for adding support for buffered, iostream oriented, epoll based I/O.
 *
 * @file
 * @brief Declaration of class OutputStream.
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

// OutputDevice.h must be included first.
#include "OutputDevice.h"

#ifndef EVIO_OUTPUT_STREAM_H
#define EVIO_OUTPUT_STREAM_H

#include "Source.h"
#include <ostream>

namespace evio {

class OutputStream : public std::ostream, public Source
{
 protected:
  OutputBuffer* create_buffer(OutputDevice* output_device, size_t buffer_full_watermark, size_t max_alloc) override
  {
    DoutEntering(dc::evio, "OutputStream::create_buffer(" << output_device << ", " << buffer_full_watermark << ", " << max_alloc << ")");
    m_output_device = output_device;
    OutputBuffer* output_buffer = new OutputBuffer(output_device, minimum_block_size(), buffer_full_watermark, max_alloc);
    [[maybe_unused]] std::streambuf* old_streambuf = rdbuf(output_buffer);
    return output_buffer;
  }
};

} // namespace evio

#endif // EVIO_OUTPUT_STREAM_H
