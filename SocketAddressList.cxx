// evio -- Event Driven I/O support.
//
//! @file
//! @brief Definition of namespace evio; class SocketAddressList.
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

#include "sys.h"
#include "debug.h"
#include "SocketAddressList.h"

namespace evio {

SocketAddressList& SocketAddressList::operator=(struct addrinfo const* info_list)
{
  mList.clear();
  for (struct addrinfo const* rp = info_list; rp != nullptr; rp = rp->ai_next)
    mList.emplace_back(rp->ai_addr);
  return *this;
}

std::ostream& operator<<(std::ostream& os, SocketAddressList const& socket_address_list)
{
  os << '{';
  char const* separator = "";
  for (auto&& socket_address : socket_address_list.mList)
  {
    os << separator << socket_address;
    separator = ", ";
  }
  return os << '}';
}

} // namespace evio
