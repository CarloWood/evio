// evio -- Event Driven I/O support.
//
//! @file
//! @brief Definition of class Socket.
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
#include "Socket.h"
#include "utils/AIAlert.h"
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
//#include <unistd.h>
#include <cstring>
#include <cerrno>

namespace evio {

bool Socket::connect(SocketAddress socket_address, size_t rcvbuf_size, size_t sndbuf_size, SocketAddress if_addr)
{
  if (is_open())
    return false;

  // The address to connect to needs to make sense.
  ASSERT(!socket_address.is_unspecified());

  if (!m_socket_address.is_unspecified())
    Dout(dc::warning, "Socket::connect: Already connected to " << m_socket_address << " ?!");

  m_socket_address = socket_address;

  m_rcvbuf_size = rcvbuf_size;
  m_sndbuf_size = sndbuf_size;

  struct sockaddr const* addr = static_cast<struct sockaddr const*>(socket_address);
  Dout(dc::system|continued_cf, "socket(" << addr->sa_family << ", SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0) = ");
  int fd = socket(addr->sa_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  Dout(dc::finish|cond_error_cf(fd < 0), fd);
  if (fd < 0)
    return false;

  if (socket_address.is_ip())
  {
    Dout(dc::warning, "FIXME: need minimum input/output buffer sizes here.");
#if 0
    if (!set_rcvsockbuf(fd, m_rcvbuf_size, minimum_input_size()) ||
	!set_sndsockbuf(fd, m_sndbuf_size, minimum_output_size()))
    {
      Dout(dc::system|continued_cf, "close(" << fd << ") = ");
      DEBUG_ONLY(int ret =) ::close(fd);
      Dout(dc::finish|cond_error_cf(ret == -1), ret);
      return false;
    }
#endif
  }
  if (!if_addr.is_unspecified())
  {
    if (bind(fd, if_addr, sizeof(struct sockaddr_in)) == -1)
      DoutFatal(dc::fatal|error_cf, "bind: " << if_addr);
  }

  Dout(dc::system|continued_cf, "connect(" << fd << ", {" << *addr << "}, " << size_of_addr(addr) << ") = ");
  int ret = ::connect(fd, addr, size_of_addr(addr));
  if (ret < 0 && errno != EINPROGRESS)
  {
    Dout(dc::finish|error_cf, ret);
    Dout(dc::system|continued_cf, "close(" << fd << ") = ");
    DEBUG_ONLY(ret =) ::close(fd);
    Dout(dc::finish|cond_error_cf(ret < 0), ret);
    return false;
  }
  Dout(dc::finish|cond_error_cf(ret < 0), ret);

  FileDescriptor::init(fd);     // link in
  start_input_device();
  if (m_obuffer && !m_obuffer->buffer_empty())
    start_output_device();

  return true;
}

SocketAddress Socket::local_address() const
{
  // Don't call this function when !is_open() (aka, init() was called).
  ASSERT(is_open());
  SocketAddress result;
  socklen_t namelen = sizeof(result);

  // Shouldn't this always be the case for a Socket?
  ASSERT(get_output_fd() == get_input_fd());
  if (getsockname(get_output_fd(), result, &namelen) < 0)
  {
    std::ostringstream descr;
    descr << "getsockname(" << get_output_fd() << ", " << std::hex << &result << ", [" << std::dec << namelen << "])";
    // This makes a copy of the string to AIAlert::Line::mXmlDesc before throwing.
    THROW_FALERTE(descr.str());
  }

  return result;
}

} // namespace evio
