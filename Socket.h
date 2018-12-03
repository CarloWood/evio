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

  // The address of the remote socket; either what we connected to or the peer address of an accepted connection.
  SocketAddress m_remote_address;

  // The receive socket buffer that we want to be set.
  // The actual size can be set to a larger value, see net/inet_support.cc
  // A value of 0 here means: use a size that depends on the minimum block
  // size of our input buffer.
  size_t m_rcvbuf_size;

  // Idem for the send socket buffer (except, output buffer).
  size_t m_sndbuf_size;

 public:
  //---------------------------------------------------------------------------
  // Constructor
  //

  Socket() : m_rcvbuf_size(0), m_sndbuf_size(0) { DoutEntering(dc::evio, "Socket::Socket() [" << this << "]"); }

  // Associate this object with an existing and open socket `fd'.
  void init(int fd, SocketAddress const& socket_address, size_t rcvbuf_size = 0, size_t sndbuf_size = 0);

  // Create a socket(2), bind it to if_addr, and call init().
  bool connect(SocketAddress socket_address, size_t rcvbuf_size = 0, size_t sndbuf_size = 0, SocketAddress if_addr = {});

 public:
  //---------------------------------------------------------------------------
  // Public accessors:
  //

  // Returns the remote IP number and port that this socket connected with.
  // Only valid when `is_open' returns true.
  SocketAddress address() const { return m_remote_address; }

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
    assert(m_remote_address.is_un());
    return reinterpret_cast<struct sockaddr_un const*>(static_cast<struct sockaddr const*>(m_remote_address))->sun_path;
  }
};

} // namespace evio
