// evio -- Event Driven I/O support.
//
//! @file
//! @brief Declaration of namespace evio; class Interface.h.
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
#include "debug.h"
#include "SocketAddress.h"
#include "SocketNetmask.h"
#include "utils/AIAlert.h"
#include <iosfwd>
#include <ifaddrs.h>

namespace evio {

class InterfaceIterator;

class Interface
{
 private:
  friend class InterfaceIterator;
  struct ifaddrs* m_ifaddr;

 public:
  Interface() : m_ifaddr(nullptr) { }
  Interface(struct ifaddrs* ifaddr) : m_ifaddr(ifaddr) { }

  // Return the name of the interface.
  char const* name() const { return m_ifaddr->ifa_name; }

  // Flags from SIOCGIFFLAGS.
  unsigned int flags() const { return m_ifaddr->ifa_flags; }

  // Address of interface.
  SocketAddress address() const { return {m_ifaddr->ifa_addr}; }

  // Netmask of interface.
  SocketNetmask netmask() const { return {m_ifaddr->ifa_netmask}; }

  friend std::ostream& operator<<(std::ostream& os, Interface const& interface);
};

class InterfaceIterator
{
 protected:
  Interface m_interface;

 public:
  InterfaceIterator() { }
  InterfaceIterator(struct ifaddrs* ifaddrs) : m_interface(ifaddrs) { }

  InterfaceIterator& operator++() { m_interface.m_ifaddr = m_interface.m_ifaddr->ifa_next; return *this; }
  InterfaceIterator operator++(int) { InterfaceIterator prev(*this); this->operator++(); return prev; }
  Interface operator*() const { return m_interface; }
  Interface const* operator->() const { return &m_interface; }

  bool operator!=(InterfaceIterator const& it2)
  {
    return m_interface.m_ifaddr !=  it2.m_interface.m_ifaddr;
  }
};

class Interfaces
{
 private:
  struct ifaddrs* m_ifaddrs;
  size_t m_size;

 public:
  Interfaces() : m_ifaddrs(nullptr), m_size(0)
  {
    DoutEntering(dc::notice, "Interfaces()");
    if (getifaddrs(&m_ifaddrs) == -1)
      THROW_ALERTE("getifaddrs()");
    for (struct ifaddrs* ifa = m_ifaddrs; ifa != nullptr; ifa = ifa->ifa_next, ++m_size)
      ;
    Dout(dc::notice, "Found " << m_size << " interfaces.");
  }
  ~Interfaces()
  {
    freeifaddrs(m_ifaddrs);
  }

  InterfaceIterator begin() const { return {m_ifaddrs}; }
  InterfaceIterator end() const { return {nullptr}; }
  bool empty() const { return m_ifaddrs == nullptr; }
  size_t size() const { return m_size; }
};

} // namespace evio
