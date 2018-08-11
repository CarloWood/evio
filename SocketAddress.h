// evio -- Event Driven I/O support.
//
//! @file
//! @brief Declaration of class SocketAddress.
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

#include <string_view>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <iosfwd>

namespace evio {

//=============================================================================
//
// class SocketAddress
//
// This class represent socket addresses, like IPv4 and IPv6 end points
// and UNIX sockets.

class SocketAddress
{
  union {
    struct {
      struct sockaddr m_sockaddr;               // The type (sa_family) of socket address.
      struct sockaddr_un* m_sockaddr_un_ptr;    // A sockaddr_un won't fit, so allocate it. Only valid when is_un().
    };
    struct sockaddr_in6 m_storage;              // Make sure a sockaddr_in6 fits.
  };

 public:
  SocketAddress() : m_sockaddr{AF_UNSPEC, 0}, m_sockaddr_un_ptr{nullptr} { }
  SocketAddress(std::string_view sockaddr_text);
  SocketAddress(SocketAddress&& other);
  SocketAddress(SocketAddress const& other);
  SocketAddress& operator=(SocketAddress&& other);
  SocketAddress& operator=(SocketAddress const& other);

  bool is_unspecified() const { return m_sockaddr.sa_family == AF_UNSPEC; }
  bool is_un() const { return m_sockaddr.sa_family == AF_UNIX; }
  bool is_ip() const { return m_sockaddr.sa_family == AF_INET || m_sockaddr.sa_family == AF_INET6; }
  bool is_ip4() const { return m_sockaddr.sa_family == AF_INET; }
  bool is_ip6() const { return m_sockaddr.sa_family == AF_INET6; }

  // Automatic conversion to struct sockaddr*.
  operator struct sockaddr const*() const { return &m_sockaddr; }

  // Conversion to a human readable string.
  std::string to_string() const;

  // Support writing to an ostream.
  friend std::ostream& operator<<(std::ostream& os, SocketAddress const& socket_address);
};

} // namespace evio
