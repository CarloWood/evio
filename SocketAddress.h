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
#include <array>
#include <system_error>

namespace evio {

//=============================================================================
//
// class SocketAddress
//
// This class represent socket addresses, like IPv4 and IPv6 end points
// and UNIX sockets.

class SocketAddress             // TestSuite: test_SocketAddress.h
{
  union {
    struct {
      struct sockaddr m_sockaddr;               // The type (sa_family) of socket address.
      struct sockaddr_un* m_sockaddr_un_ptr;    // A sockaddr_un won't fit, so allocate it. Only valid when is_un().
    };
    struct sockaddr_in6 m_storage;              // Make sure a sockaddr_in6 fits.
  };

 public:
  SocketAddress() : m_sockaddr{AF_UNSPEC, {0, }}, m_sockaddr_un_ptr{nullptr} { }
  // Construct a SocketAddress from a string_view.
  // If sockaddr_text starts with a '/' then AF_UNIX is assumed,
  // otherwise AF_INET6 is assumed if the address portion contains a ':' (for example "[::ffff:127.0.0.1]:9001" will be AF_INET6,
  // but "[127.0.0.1]:9001" will not), otherwise AF_INET is assumed. If the format is invalid then the constructor will throw.
  SocketAddress(std::string_view sockaddr_text) { decode_sockaddr(sockaddr_text, AF_UNSPEC); }
  // Force the socket family; this will throw if the provided sockaddr_text cannot be parsed as sa_family.
  SocketAddress(sa_family_t sa_family, std::string_view sockaddr_text) { decode_sockaddr(sockaddr_text, sa_family); }
  // Force AF_INET or AF_INET6 and provide the port number separately.
  // sin_addr_text must be the address portion (for example "::1", or "192.168.1.1").
  SocketAddress(std::string_view sin_addr_text, uint16_t port) { decode_sockaddr(sin_addr_text, AF_UNSPEC, port); }
  // Same as above but force to socket family.
  SocketAddress(sa_family_t sin_family, std::string_view sin_addr_text, uint16_t port) { decode_sockaddr(sin_addr_text, sin_family, port); }
  // Construct a SocketAddress from a fully initialized struct sockaddr_in (AF_INET),
  // struct sockaddr_in6 (AF_INET6) or struct sockaddr_un (AF_UNIX).
  SocketAddress(struct sockaddr const* sa_addr) { init(sa_addr); }
  // Same, but ignore the port number in sa_addr and use port instead.
  SocketAddress(struct sockaddr const* sa_addr, uint16_t port) { init(sa_addr, port); }
  // Move constructor (only useful for AF_UNIX sockets).
  SocketAddress(SocketAddress&& other) { move(std::move(other)); }
  // Copy constructor.
  SocketAddress(SocketAddress const& other) { init(other); }
  // Move assignment.
  SocketAddress& operator=(SocketAddress&& other) { deinit(); move(std::move(other)); return *this; }
  // Copy assignment.
  SocketAddress& operator=(SocketAddress const& other) { deinit(); init(other); return *this; }
  // Destructor.
  ~SocketAddress() { deinit(); }

  bool is_unspecified() const { return m_sockaddr.sa_family == AF_UNSPEC; }
  bool is_un() const { return m_sockaddr.sa_family == AF_UNIX; }
  bool is_ip() const { return m_sockaddr.sa_family == AF_INET || m_sockaddr.sa_family == AF_INET6; }
  bool is_ip4() const { return m_sockaddr.sa_family == AF_INET; }
  bool is_ip6() const { return m_sockaddr.sa_family == AF_INET6; }
  bool is_unknown() const { return !is_unspecified() && !is_un() && !is_ip(); }

  // Automatic conversion to struct sockaddr*.
  operator struct sockaddr const*() const { return is_un() ? reinterpret_cast<struct sockaddr const*>(m_sockaddr_un_ptr) : &m_sockaddr; }
  operator struct sockaddr*() { return is_un() ? reinterpret_cast<struct sockaddr*>(m_sockaddr_un_ptr) : &m_sockaddr; }

  // Low level access.
  sa_family_t family() const { return m_sockaddr.sa_family; }

  // Conversion to a human readable string.
  std::string to_string(bool no_port = false) const;

  // Convert to arpa address.
  using arpa_buf_t = std::array<char, 74>;
  void ptr_qname(arpa_buf_t& arpa_out_buf) const;

  // Comparison.
  friend bool operator!=(SocketAddress const& sa1, SocketAddress const& sa2) { return !sa1.compare_with(sa2, 0); }
  friend bool operator==(SocketAddress const& sa1, SocketAddress const& sa2) { return sa1.compare_with(sa2, 0); }
  friend bool operator<(SocketAddress const& sa1, SocketAddress const& sa2) { return sa1.compare_with(sa2, -1); }

  // Support writing to an ostream.
  friend std::ostream& operator<<(std::ostream& os, SocketAddress const& socket_address);

 private:
  void deinit();
  void decode_sockaddr(std::string_view sin_addr_text, sa_family_t sa_family, int port_h = -1);
  void make_sockaddr_un(std::string_view sockaddr_text);
  void move(SocketAddress&& other);
  void init(struct sockaddr const* sa_addr);
  void init(struct sockaddr const* sa_addr, uint16_t port);
  void init(SocketAddress const& other)
      { init(other.is_un() ? reinterpret_cast<struct sockaddr const*>(other.m_sockaddr_un_ptr)
                           : &other.m_sockaddr); }
  bool compare_with(SocketAddress const& sa, int val) const;
};

enum error_codes
{
  SocketAddress_decode_sockaddr_parse_error = -1,
  SocketAddress_make_sockaddr_un_path_too_long = 1
};

std::error_code make_error_code(error_codes);

} // namespace evio

// Register evio::error_codes as valid error code.
namespace std {

template<> struct is_error_code_enum<evio::error_codes> : true_type { };

} // namespace std
