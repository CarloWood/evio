/**
 * evio -- A cwm4 git submodule for adding support for buffered, iostream oriented, epoll based I/O.
 *
 * @file
 * @brief Declaration of class InAddr.
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

#include <iosfwd>
#include <sys/types.h>

struct hostent;
struct sockaddr;
struct in_addr;
struct in6_addr;

namespace evio {

int print_hostent_on(struct hostent const* h, std::ostream& o);                         // Testsuite: test_print_hostent_on.h
void set_sndsockbuf(int sock_fd, size_t sndbuf_size, size_t minimum_block_size);        // Testsuite: test_set_XXXsockbuf.h
void set_rcvsockbuf(int sock_fd, size_t rcvbuf_size, size_t minimum_block_size);        // Testsuite: test_set_XXXsockbuf.h
size_t size_of_addr(struct sockaddr const* addr);                                       // Testsuite: test_size_of_addr.h

} // namespace evio

std::ostream& operator<<(std::ostream& os, struct in_addr const& in);                   // Wrapper around inet_ntop(3).
std::ostream& operator<<(std::ostream& os, struct in6_addr const& in6);                 // Wrapper around inet_ntop(3).
#if 0 // Use SocketAddress
std::ostream& operator<<(std::ostream& os, struct sockaddr_in const& s);
std::ostream& operator<<(std::ostream& os, struct sockaddr_un const& s);
std::ostream& operator<<(std::ostream& os, struct sockaddr const& s);
#endif
