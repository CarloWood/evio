/**
 * evio -- A cwm4 git submodule for adding support for buffered, iostream oriented, epoll based I/O.
 *
 * @file
 * @brief Declaration of class SocketAddressList.
 *
 * @Copyright (C) 2018  Carlo Wood.
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

#include "SocketAddress.h"
#include <vector>
#include <netdb.h>              // struct addrinfo.

namespace evio {

//=============================================================================
//
// class SocketAddressList
//
// This class represent a list (zero or more) of SocketAddress objects.

class SocketAddressList
{
 private:
  std::vector<SocketAddress> mList;

 public:
  SocketAddressList() = default;
  SocketAddressList(SocketAddressList&& socket_address_list) : mList(std::move(socket_address_list.mList)) { }
  SocketAddressList(SocketAddressList const& socket_address_list) : mList(socket_address_list.mList) { }

  SocketAddressList& operator=(SocketAddressList&& socket_address_list) { mList = std::move(socket_address_list.mList); return *this; }
  SocketAddressList& operator=(SocketAddressList const& socket_address_list) { mList = socket_address_list.mList; return *this; }

  SocketAddressList& operator+=(SocketAddress&& sockaddr) { mList.push_back(std::move(sockaddr)); return *this; }
  SocketAddressList& operator+=(SocketAddress const& sockaddr) { mList.push_back(sockaddr); return *this; }

  SocketAddressList& operator=(struct addrinfo const* info_list);
  SocketAddressList(struct addrinfo const* info_list) { *this = info_list; }

  void clear() { mList.clear(); }
  size_t size() const { return mList.size(); }
  bool empty() const { return mList.empty(); }
  std::vector<SocketAddress>::iterator begin() { return mList.begin(); }
  std::vector<SocketAddress>::const_iterator end() const { return mList.end(); }

  friend std::ostream& operator<<(std::ostream& os, SocketAddressList const& socket_address_list);
};

} // namespace evio
