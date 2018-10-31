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
#include "inet_support.h"
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstring>
#include <cerrno>

namespace evio {

bool SocketDevice::priv_connect(struct sockaddr* addr, size_t rcvbuf_size, size_t sndbuf_size, struct sockaddr* bind_addr = nullptr)
{
  if (is_open())
    return false;

  if (m_addr)
  {
    Dout(dc::warning, "SocketDevice::priv_in_connect: Already connected to " << addr << " ?!");
    free(m_addr);
  }
  m_addr = addr;
  if (m_local_addr)
    free(m_local_addr);
  m_local_addr = bind_addr;
  m_rcvbuf_size = rcvbuf_size;
  m_sndbuf_size = sndbuf_size;

  Dout(dc::system|continued_cf, "socket(" << addr->sa_family << ", SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0) = ");
  int fd = socket(addr->sa_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  Dout(dc::finish|cond_error_cf(fd < 0), fd);
  if (fd < 0)
    return false;

  if (m_addr->sa_family == AF_INET || m_addr->sa_family == AF_INET6)
  {
    if (!set_rcvsockbuf(fd, m_rcvbuf_size, minimum_input_size()) ||
	!set_sndsockbuf(fd, m_sndbuf_size, minimum_output_size()))
    {
      Dout(dc::system|continued_cf, "close(" << fd << ") = ");
      DEBUG_ONLY(int ret =) ::close(fd);
      Dout(dc::finish|cond_error_cf(ret == -1), ret);
      return false;
    }
    if (m_local_addr)
    {
      if (bind(fd, m_local_addr, sizeof(struct sockaddr_in)) == -1)
        DoutFatal(dc::fatal|error_cf, "bind: " << reinterpret_cast<struct sockaddr_in*>(m_local_addr)->sin_addr);
    }
  }
  else
  {
    ASSERT(m_local_addr == nullptr);
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

  IOBase::init(fd);     // link in
  start();

  return true;
}

bool SocketDevice::priv_in_connect(struct in_addr ip, unsigned short int port, size_t rcvbuf_size, size_t sndbuf_size)
{
  struct sockaddr_in* in_addr = (struct sockaddr_in*)malloc(sizeof(struct sockaddr_in));
  AllocTag(in_addr, "SocketDevice::addr");
  in_addr->sin_family = AF_INET;
  in_addr->sin_port = htons(port);
  in_addr->sin_addr = ip;
  return priv_connect(reinterpret_cast<struct sockaddr*>(in_addr), rcvbuf_size, sndbuf_size);
}

bool SocketDevice::priv_in_connect(struct in_addr ip, unsigned short int port, struct in_addr local_ip, size_t rcvbuf_size, size_t sndbuf_size)
{
  struct sockaddr_in* in_addr = (struct sockaddr_in*)malloc(sizeof(struct sockaddr_in));
  AllocTag(in_addr, "SocketDevice::addr");
  in_addr->sin_family = AF_INET;
  in_addr->sin_port = htons(port);
  in_addr->sin_addr = ip;
  struct sockaddr_in* local_addr = (struct sockaddr_in*)malloc(sizeof(struct sockaddr_in));
  AllocTag(local_addr, "SocketDevice::local_addr");
  local_addr->sin_family = AF_INET;
  local_addr->sin_port = 0;
  local_addr->sin_addr = local_ip;
  return priv_connect(reinterpret_cast<struct sockaddr*>(in_addr),
         rcvbuf_size, sndbuf_size,
         reinterpret_cast<struct sockaddr*>(local_addr));
}

bool SocketDevice::priv_in_connect(char const* host, unsigned short int port, size_t rcvbuf_size, size_t sndbuf_size)
{
  struct hostent* h = gethostbyname(host);	// FIXME: This is blocking

  if (h && !h->h_addr_list[0])
  {
    h_errno = NO_DATA;
    h = nullptr;
  }
  if (!h)
  {
    Dout(dc::warning, "gethostbyname: " << strherror(h_errno));
    return false;
  }

  struct in_addr ip = *(struct in_addr*)h->h_addr_list[0];
    // h_addr_list is static, I don't want to take risks.

  return priv_in_connect(ip, port, rcvbuf_size, sndbuf_size);
}

bool SocketDevice::priv_in_connect(char const* host, unsigned short int port, struct in_addr local_ip, size_t rcvbuf_size, size_t sndbuf_size)
{
  struct hostent* h = gethostbyname(host);	// FIXME: This is blocking

  if (h && !h->h_addr_list[0])
  {
    h_errno = NO_DATA;
    h = nullptr;
  }
  if (!h)
  {
    Dout(dc::warning, "gethostbyname: " << strherror(h_errno));
    return false;
  }

  struct in_addr ip = *(struct in_addr*)h->h_addr_list[0];
    // h_addr_list is static, I don't want to take risks.

  return priv_in_connect(ip, port, local_ip, rcvbuf_size, sndbuf_size);
}

bool SocketDevice::priv_un_connect(char const* path, size_t rcvbuf_size, size_t sndbuf_size)
{
  struct sockaddr_un* un_addr;
#ifdef CWDEBUG
  if (sizeof(un_addr->sun_family) + strlen(path) + 1 > sizeof(struct sockaddr_un))
    DoutFatal(dc::core, "SocketDevice::priv_un_connect: path too long");
#endif
  un_addr = (struct sockaddr_un*)malloc(sizeof(un_addr->sun_family) + strlen(path) + 1);
  AllocTag(un_addr, "SocketDevice::addr");
  un_addr->sun_family = AF_UNIX;
  strcpy(un_addr->sun_path, path);
  return priv_connect((struct sockaddr*)un_addr, rcvbuf_size, sndbuf_size);
}

struct in_addr SocketDevice::local_ip() const
{
#ifdef CWDEBUG
  if (!m_addr || m_addr->sa_family != AF_INET)
    DoutFatal(dc::core, "Calling SocketDevice::local_ip for a non AF_INET socket");
#endif
  struct sockaddr_in local_addr;
  socklen_t namelen = sizeof(local_addr);

  ASSERT(get_output_fd() == get_input_fd());
  if (getsockname(get_output_fd(), (struct sockaddr*)&local_addr, &namelen) < 0)
  {
    Dout(dc::warning|error_cf, "SocketDevice::local_ip: getsockname(" << get_output_fd() << ", " << std::hex << &local_addr << ", [" << namelen << "])");
    struct in_addr dummy;
    memset(&dummy, 0, sizeof(dummy));
    return dummy;
  }

  return local_addr.sin_addr;
}

unsigned short int SocketDevice::local_port() const
{
#ifdef CWDEBUG
  if (!m_addr || m_addr->sa_family != AF_INET)
    DoutFatal(dc::core, "Calling SocketDevice::local_port for a non AF_INET socket");
#endif
  struct sockaddr_in local_addr;
  socklen_t namelen = sizeof(local_addr);

  ASSERT(get_output_fd() == get_input_fd());
  if (getsockname(get_output_fd(), (struct sockaddr*)&local_addr, &namelen) < 0)
  {
    Dout(dc::warning|error_cf, "SocketDevice::local_port: getsockname(" << get_output_fd() << ", " << std::hex << &local_addr << ", [" << namelen << "])");
    return 0;
  }

  return local_addr.sin_port;
}

} // namespace evio
