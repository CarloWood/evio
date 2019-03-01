// evio -- Event Driven I/O support.
//
//! @file
//! @brief Declaration of class InAddr.
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

#include <iosfwd>
#include <sys/types.h>

struct hostent;
struct sockaddr;
struct in_addr;
struct sockaddr_in;
struct sockaddr_un;

namespace evio {

int print_hostent_on(struct hostent const* h, std::ostream& o);
void set_sndsockbuf(int sock_fd, size_t sndbuf_size, size_t minimum_block_size);
void set_rcvsockbuf(int sock_fd, size_t rcvbuf_size, size_t minimum_block_size);
size_t size_of_addr(struct sockaddr const* addr);

} // namespace evio

std::ostream& operator<<(std::ostream& os, struct in_addr const& in);
#if 0 // Use SocketAddress
std::ostream& operator<<(std::ostream& os, struct sockaddr_in const& s);
std::ostream& operator<<(std::ostream& os, struct sockaddr_un const& s);
std::ostream& operator<<(std::ostream& os, struct sockaddr const& s);
#endif
