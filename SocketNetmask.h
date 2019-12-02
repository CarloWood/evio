/**
 * evio -- A cwm4 git submodule for adding support for buffered, iostream oriented, epoll based I/O.
 *
 * @file
 * @brief Declaration of class SocketNetmask.
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

#pragma once

namespace evio {

//=============================================================================
//
// class SocketNetmask
//
// This class represent socket netmasks for IPv4 and IPv6 addresses.

class SocketNetmask
{
 private:
  SocketAddress m_netmask;

 public:
  SocketNetmask() { }
  //SocketAddress(std::string_view sockaddr_text)
  //SocketAddress(sa_family_t sa_family, std::string_view sockaddr_text)

  // Construct a SocketNetmask from a fully initialized struct sockaddr_in (AF_INET) or struct sockaddr_in6 (AF_INET6).
  SocketNetmask(struct sockaddr const* sa_addr) : m_netmask(sa_addr) { /* A netmask must be AF_INET or AF_INET6 */ ASSERT(m_netmask.is_ip()); }
  // Move constructor.
  SocketNetmask(SocketNetmask&& other) : m_netmask(std::move(other.m_netmask)) { }
  // Copy constructor.
  SocketNetmask(SocketNetmask const& other) : m_netmask(other.m_netmask) { }
  // Move assignment.
  SocketNetmask& operator=(SocketNetmask&& other) { m_netmask = std::move(other.m_netmask); return *this; }
  // Copy assignment.
  SocketNetmask& operator=(SocketNetmask const& other) { m_netmask = std::move(other.m_netmask); return *this; }

  bool is_unspecified() const { return m_netmask.is_unspecified(); }
  bool is_ip() const { return m_netmask.is_ip(); }
  bool is_ip4() const { return m_netmask.is_ip4(); }
  bool is_ip6() const { return m_netmask.is_ip6(); }

  // Automatic conversion to struct sockaddr*.
  operator struct sockaddr const*() const { return m_netmask; }
  operator struct sockaddr*() { return m_netmask; }

  // Low level access.
  sa_family_t family() const { return m_netmask.family(); }

  // Conversion to a human readable string.
  std::string to_string() const { return m_netmask.to_string(true); }

  // Comparison.
  friend bool operator!=(SocketNetmask const& sa1, SocketNetmask const& sa2) { return sa1.m_netmask != sa2.m_netmask; }
  friend bool operator==(SocketNetmask const& sa1, SocketNetmask const& sa2) { return sa1.m_netmask == sa2.m_netmask; }
  friend bool operator<(SocketNetmask const& sa1, SocketNetmask const& sa2) { return sa1.m_netmask < sa2.m_netmask; }

  bool operator==(SocketAddress const& address)
  {
    if (m_netmask.family() != address.family() || m_netmask.is_unspecified())
      return false;

    struct sockaddr const* sa_netmask = static_cast<struct sockaddr const*>(m_netmask);
    struct sockaddr const* sa_address = static_cast<struct sockaddr const*>(address);
    if (m_netmask.family() == AF_INET)
      return !(~reinterpret_cast<struct sockaddr_in const*>(sa_netmask)->sin_addr.s_addr & reinterpret_cast<struct sockaddr_in const*>(sa_address)->sin_addr.s_addr);
    // else AF_INET6
    for (int i = 0; i < 4; ++i)
    {
      if ((~reinterpret_cast<struct sockaddr_in6 const*>(sa_netmask)->sin6_addr.s6_addr32[i] & reinterpret_cast<struct sockaddr_in6 const*>(sa_address)->sin6_addr.s6_addr32[i]))
        return false;
    }
    return true;
  }

  // Support writing to an ostream.
  friend std::ostream& operator<<(std::ostream& os, SocketNetmask const& socket_netmask) { return os << socket_netmask.to_string(); }

 private:
  //void decode_netmask(std::string_view sin_addr_text, sa_family_t sa_family);
};

} // namespace evio
