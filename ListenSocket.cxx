// evio -- Event Driven I/O support.
//
//! @file
//! @brief Definition of class ListenSocket.
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
#include "ListenSocket.h"
#include "utils/AIAlert.h"

namespace evio {

void ListenSocketDevice::listen(SocketAddress&& bind_addr, int backlog)
{
  // Don't call listen() twice on a row. First close() the listen socket again.
  ASSERT(!is_open());

  Dout(dc::system|continued_cf, "socket(" << bind_addr.family() << ", SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0) = ");
  int fd = socket(bind_addr.family(), SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
#ifdef CWDEBUG
  int errn = errno;
  // Need to give the namespace inside templates for the cond_* due to bug in compiler.
  Dout(dc::finish|cond_error_cf(fd < 0), fd);
  errno = errn;
#endif
  if (fd < 0)
  {
    THROW_ALERTE("socket([FAMILY], SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0) = [FD]",
        AIArgs("[FAMILY]", bind_addr.family())("[FD]", fd));
  }

#ifdef SO_REUSEADDR
  if (bind_addr.is_ip())
  {
    int opt = 1;
    // Some OS need (optval_t)&opt, glibc doesn't (libc-5 does).
    DEBUG_ONLY(int res =) ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    Dout(dc::warning(res < 0)|error_cf, "ListenSocketDevice::listen: setsockopt(SO_REUSEADDR)");
  }
#endif // SO_REUSEADDR

  for (;;)
  {
    if (::bind(fd, bind_addr, size_of_addr(bind_addr)) == 0)
    {
      Dout(dc::system, "bind(" << fd << ", " << bind_addr << ", " << size_of_addr(bind_addr) << ") = 0");
      break;
    }
    if (bind_addr.is_un() && errno == EADDRINUSE)
    {
      struct sockaddr_un const* un = reinterpret_cast<struct sockaddr_un const*>(static_cast<struct sockaddr const*>(bind_addr));
      Dout(dc::system|continued_cf, "unlink(\"" << un->sun_path << "\") = ");
      int res = ::unlink(un->sun_path);
      Dout(dc::finish|cond_error_cf(res == -1), res);
      if (res == 0)
	continue;
      errno = EADDRINUSE;
    }
    int errn = errno;
    Dout(dc::system|continued_cf, "close(" << fd << ") = ");
    DEBUG_ONLY(int res =) ::close(fd);
    Dout(dc::finish|cond_error_cf(res == -1), res);
    errno = errn;
    THROW_ALERTE("bind([FD], [BIND_ADDR], [SIZE]) = -1",
        AIArgs("[FD]", fd)("[BIND_ADDR]", bind_addr)("[SIZE]", size_of_addr(bind_addr)));
  }
  m_bind_addr = std::move(bind_addr);   // m_bind_addr should only be set after a successful bind(2).

  int res = ::listen(fd, backlog);
  if (res == -1)
  {
    int errn = errno;
    Dout(dc::system|continued_cf, "close(" << fd << ") = ");
    DEBUG_ONLY(int res2 =) ::close(fd);
    Dout(dc::finish|cond_error_cf(res2 == -1), res2);
    errno = errn;
    THROW_ALERTE("listen([FD], [BACKLOG]) = -1", AIArgs("[FD]", fd)("[BACKLOG]", backlog));
  }
  else
    Dout(dc::system, "listen(" << fd << ", " << backlog << ") = " << res);

  init(fd);
  Dout(dc::notice, "Added listen socket " << fd << " at " << m_bind_addr);

  // input() does not need to be called here, because we override read_from_fd.
  start_input_device();
}

void ListenSocketDevice::read_from_fd(int fd)
{
  int sock_fd;
  socklen_t addrlen = sizeof(struct sockaddr);
  struct sockaddr* accept_addr = (struct sockaddr*)malloc(sizeof(struct sockaddr));
  AllocTag(accept_addr, "struct sockaddr*" << libcwd::type_info_of(*this).demangled_name() << "::accept_addr");

  Dout(dc::system|continued_cf, "accept4(" << fd << ", " << accept_addr << ", ");
  if ((sock_fd = accept4(fd, accept_addr, &addrlen, SOCK_NONBLOCK | SOCK_CLOEXEC)) == -1)
  {
    int err = errno;
    Dout(dc::finish|error_cf, (void*)&addrlen << ") = " << sock_fd);
    if (err != EWOULDBLOCK && maybe_out_of_fds())
      err = EMFILE;
#ifdef CWDEBUG
    errno = err;
    Dout(dc::warning|error_cf, libcwd::type_info_of(*this).demangled_name() << "::read_from_fd: accept");
    if (err != EWOULDBLOCK)
      Dout(dc::warning, libcwd::type_info_of(*this).demangled_name() << "::read_from_fd: Need to throw exception: accept failed");
#endif
    free(accept_addr);
    return;
  }
  Dout(dc::finish, '{' << addrlen << "}, SOCK_NONBLOCK | SOCK_CLOEXEC) = " << sock_fd);
  Dout(dc::notice, "accepted a new client on fd " << sock_fd << " from " << *accept_addr);

  spawn_accepted(sock_fd, accept_addr);

#if 0   // FIXME Set socket buffer sizes.
  if (accept_addr->sa_family == AF_INET)
  {
    input_ct* id = d;
    output_ct* od = d;
    if (!set_rcvsockbuf(sock_fd, d->get_rcvbuf_size(), id->rddbbuf()->minimum_block_size()) ||
	!set_sndsockbuf(sock_fd, d->get_sndbuf_size(), od->rddbbuf()->minimum_block_size()))
    {
      d->del();
      return;
    }
  }
#endif
}

bool ListenSocketDevice::maybe_out_of_fds()
{
  int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd >= 0)
    ::close(fd);
  return fd == -1;
}

} // namespace evio
