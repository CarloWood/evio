/**
 * evio -- A cwm4 git submodule for adding support for buffered, iostream oriented, epoll based I/O.
 *
 * @file
 * @brief Definition of class Decoder.
 *
 * @Copyright (C) 2019  Carlo Wood.
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

#include "sys.h"
#include "evio/InputDevice.h"
#include "Decoder.h"
#include "debug.h"

namespace evio {
namespace protocol {

size_t Decoder::end_of_msg_finder(char const* new_data, size_t rlen, EndOfMsgFinderResult& UNUSED_ARG(result))
{
  DoutEntering(dc::endofmsg, "Decoder::end_of_msg_finder(..., " << rlen << ")");
  char const* newline = static_cast<char const*>(std::memchr(new_data, '\n', rlen));
  return newline ? newline - new_data + 1 : 0;
}

} // namespace protocol
} // namespace evio
