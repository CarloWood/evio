// evio -- Event Driven I/O support.
//
//! @file
//! @brief Declaration of class AcceptedSocket.
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

#include "Socket.h"

namespace evio {

template<typename INPUTDECODER, typename OUTPUTDEVICEPTR>
class AcceptedSocket : public Socket
{
  static_assert(std::is_base_of_v<InputDecoder, INPUTDECODER>, "INPUTDECODER must be derived from evio::InputDecoder.");
  static_assert(std::is_base_of_v<OutputDevicePtr, OUTPUTDEVICEPTR>, "OUTPUTDEVICEPTR must be derived from evio::OutputDevicePtr (e.g. evio::OutputStream).");
 public:
  // These are using by ListenSocketDevice.
  using input_protocol_type = INPUTDECODER;
  using output_protocol_type = OUTPUTDEVICEPTR;

 protected:
  INPUTDECODER m_input;
  OUTPUTDEVICEPTR m_output;

 public:
  AcceptedSocket()
  {
#if CWDEBUG_LOCATION
    DoutEntering(dc::evio, "AcceptedSocket<" << libcwd::type_info_of<INPUTDECODER>().demangled_name() << ", " << libcwd::type_info_of<OUTPUTDEVICEPTR>().demangled_name() << ">()");
#else
    DoutEntering(dc::evio, "AcceptedSocket<>()");
#endif
    set_sink(m_input);
    set_source(m_output);
  }

  ~AcceptedSocket() noexcept
  {
#if CWDEBUG_LOCATION
    Dout(dc::evio, "~AcceptedSocket<" << libcwd::type_info_of<INPUTDECODER>().demangled_name() << ", " << libcwd::type_info_of<OUTPUTDEVICEPTR>().demangled_name() << ">()");
#else
    Dout(dc::evio, "~AcceptedSocket<>()");
#endif
  }

  evio::OutputStream& operator()() { return m_output; }
};

} // namespace evio
