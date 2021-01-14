/**
 * evio -- A cwm4 git submodule for adding support for buffered, iostream oriented, epoll based I/O.
 *
 * @file
 * @brief Definition of class DecoderStream.
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
#include "DecoderStream.h"
#include "debug.h"

namespace evio {
namespace protocol {

size_t DecoderStream::end_of_msg_finder(char const* new_data, size_t rlen, EndOfMsgFinderResult& result)
{
  DoutEntering(dc::io|continued_cf, "DecoderStream::end_of_msg_finder(..., " << rlen << ") = ");

  if (AI_UNLIKELY(m_message_length == -1))        // Not initialized yet.
  {
    // The callback m_get_message_length must be set. You can set it by calling DecoderStream::set_next_decoder.
    // If you do not HAVE a message length then it makes little sense to use this function.
    // In that case you should override end_of_msg_finder with whatever is your end_of_msg_finder_stream now.
    ASSERT(m_get_message_length);
    m_message_length = m_get_message_length();
  }

  size_t found_len;

  // Switch decoder if the total number of bytes received is m_message_length or greater.
  if (AI_LIKELY((m_total_len += rlen) < m_message_length))
    found_len = end_of_msg_finder_stream(new_data, rlen);
  else
  {
    Dout(dc::io, "Received " << m_total_len << " bytes in total now (m_message_length = " << m_message_length << ")");
    found_len = rlen - (m_total_len - m_message_length);
    result.m_new_decoder = m_next_decoder;
  }

  result.m_sink_type = evio::decoder_stream_sink;
  Dout(dc::finish, found_len << "[new_data = " << (void*)new_data << "; end = " << (void*)(new_data + found_len) << "(\"" << libcwd::buf2str(new_data + found_len, rlen - found_len) << "\")]");
  return found_len;
}

size_t DecoderStream::end_of_msg_finder_stream(char const* new_data, size_t rlen)
{
  return 0;
}

} // namespace protocol
} // namespace evio
