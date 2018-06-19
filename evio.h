// evio -- Event Driven I/O support.
//
//! @file
//! @brief Definition of evio::events_type and declaration of libev functions and structs.
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

#pragma once

#include "libev-4.24/ev.h"

namespace evio {

enum events_type
{
  UNDEF    = EV_UNDEF,  // Guaranteed to be invalid.
  NONE     = EV_NONE,   // No events.
  READ     = EV_READ,                   // For registering a fd that is readble, or as revents when libev detected that a read will not block.
  WRITE    = EV_WRITE,                  // For registering a fd that is writable, or as revents when libev detected that a write will not block.
  READ_WRITE = EV_READ | EV_WRITE,      // For registering a fd that is both readable and writable.
  CUSTOM   = EV_CUSTOM, // For use by user code.
  ERROR    = EV_ERROR   // Sent when an error occurs.
};

} // namespace evio
