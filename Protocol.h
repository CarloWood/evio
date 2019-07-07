// evio -- Event Driven I/O support.
//
//! @file
//! @brief Declaration of namespace evio; class Protocol.
//
// Copyright (C) 2019 Carlo Wood.
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

#pragma once

#include "sys.h"
#include "evio/StreamBuf.h"
#include "utils/nearest_power_of_two.h"
#include <algorithm>
#include <iosfwd>

namespace evio {

// Base class for Protocol classes.
//
class Protocol
{
 public:
  // This really should be defined in the derived Protocol class; however, a size of 512 isn't so large that it would be a disadvantage
  // and in most cases is will be actually larger than the real average message length, so using this as default should be possible
  // in many cases.
  //
  // The actual meaning of this is to increase the chance that after receiving a message it will be contiguous in the input buffer.
  // For this the minimum block size of the receive buffer will be set to sixteen times this value. The kernel socket buffer (which is
  // twice the SO_RCVBUF set with setsockopt) will be set to rcvbuf_size() which is by default also equal to the minimum block size.
  virtual size_t average_message_length() const { return 512; }

  virtual size_t minimum_block_size_estimate() const { return 16 * average_message_length(); }
  virtual size_t minimum_block_size() const { return utils::nearest_power_of_two(minimum_block_size_estimate()) - evio::block_overhead_c; }
//  virtual size_t rcvbuf_size() const { return minimum_block_size(); }
//  virtual size_t sndbuf_size() const { return std::max(65536UL, rcvbuf_size()); }

  friend std::ostream& operator<<(std::ostream& os, Protocol const& protocol);
};

} // namespace evio
