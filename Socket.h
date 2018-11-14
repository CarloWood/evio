// evio -- Event Driven I/O support.
//
//! @file
//! @brief Declaration of class Socket.
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

#include "SocketAddress.h"
#include "InputDevice.h"
#include "OutputDevice.h"
#include "inet_support.h"
#include "debug.h"
#include <netinet/in.h>
#include <sys/un.h>

namespace evio {

//=============================================================================
//
// class Socket
//
// SYNOPSIS
//
// This class implements connect() for "client" sockets.
//

class Socket : public InputDevice, public OutputDevice
{
 protected:
  //---------------------------------------------------------------------------
  // Protected attributes
  //

  // The connect point, nullptr when not yet initialized.
  SocketAddress m_socket_address;

  // The receive socket buffer that we want to be set.
  // The actual size can be set to a larger value, see net/inet_support.cc
  // A value of 0 here means: use the same size as the size of our buffer.
  size_t m_rcvbuf_size;

  // Idem for the send socket buffer.
  size_t m_sndbuf_size;

  //---------------------------------------------------------------------------
  // Constructor
  //

  Socket() : m_rcvbuf_size(0), m_sndbuf_size(0) { DoutEntering(dc::evio, "Socket::Socket() [" << this << "]"); }

#if CWDEBUG
  friend std::ostream& operator<<(std::ostream& os, Socket const* sdptr)
  {
    return os << static_cast<void const*>(static_cast<FileDescriptor const*>(sdptr));
  }
#endif

 protected:
//  virtual size_t minimum_input_size() const = 0;
//  virtual size_t minimum_output_size() const = 0;

 public:
  bool connect(SocketAddress socket_address, size_t rcvbuf_size = 0, size_t sndbuf_size = 0, SocketAddress if_addr = {});

  // Associate this object with an existing and open socket `fd'.
  void init(int fd, SocketAddress const& socket_address, size_t rcvbuf_size = 0, size_t sndbuf_size = 0)
  {
#ifdef CWDEBUG
    if (is_open())
      DoutFatal(dc::core, "Trying to `init' a Socket that is already open.");
#endif
    m_socket_address = socket_address;
    m_rcvbuf_size = rcvbuf_size;
    m_sndbuf_size = sndbuf_size;
    Dout(dc::warning, "FIXME: need minimum input and output buffersizes here.");
#if 0
    if (!set_rcvsockbuf(fd, m_rcvbuf_size, minimum_input_size()) ||
	!set_sndsockbuf(fd, m_sndbuf_size, minimum_output_size()))
    {
      // Why does this happen?
      ASSERT(false);
      return;
    }
#endif
    FileDescriptor::init(fd);
    start_input_device();
    start_output_device();
  }

 public:
  //---------------------------------------------------------------------------
  // Public accessors:
  //

  // Returns the remote IP number and port that this socket connected with.
  // Only valid when `is_open' returns true.
  SocketAddress address() const { return m_socket_address; }

  // Returns the local IP number and port of this socket (the bind address).
  // Only valid when `is_open' returns true.
  SocketAddress local_address() const;

  // Accessor for m_rcvbuf_size.
  size_t get_rcvbuf_size() const { return m_rcvbuf_size; }

  // Accessor for m_sndbuf_size.
  size_t get_sndbuf_size() const { return m_sndbuf_size; }

  char const* get_path() const
  {
    // Don't call get_path for a non AF_UNIX socket.
    assert(m_socket_address.is_un());
    return reinterpret_cast<struct sockaddr_un const*>(static_cast<struct sockaddr const*>(m_socket_address))->sun_path;
  }
};

} // namespace evio
