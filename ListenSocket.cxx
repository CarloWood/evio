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

namespace evio {

bool ListenSocketDevice::priv_listen(struct sockaddr* bind_addr, int backlog)
{
  if (is_open())
    return false;

  Dout(dc::system|continued_cf, "socket(" << bind_addr->sa_family << ", SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0) = ");
  int fd = socket(bind_addr->sa_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  // Need to give the namespace inside templates for the cond_* due to bug in compiler.
  Dout(dc::finish|cond_error_cf(fd < 0), fd);
  if (fd < 0)
    return false;

#ifdef SO_REUSEADDR
  if (bind_addr->sa_family == AF_INET)
  {
    int opt = 1;
#  ifdef CWDEBUG
    // Some OS need (optval_t)&opt, glibc doesn't (libc-5 does).
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
      Dout(dc::warning|error_cf, "listen_sock_dtct::listen: setsockopt(SO_REUSEADDR)");
#  else
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#  endif
  }
#endif // SO_REUSEADDR

  for (;;)
  {
    if (bind(fd, bind_addr, size_of_addr(bind_addr)) == 0)
    {
      Dout(dc::system, "bind(" << fd << ", " << *bind_addr << ", " << size_of_addr(bind_addr) << ") = 0");
      break;
    }
    if (bind_addr->sa_family == AF_UNIX && errno == EADDRINUSE)
    {
      int err = errno;
      Dout(dc::system|continued_cf, "unlink(\"" << ((struct sockaddr_un*)bind_addr)->sun_path << "\") = ");
      int res = unlink(((struct sockaddr_un*)bind_addr)->sun_path);
      Dout(dc::finish|cond_error_cf(res == -1), res);
      if (res == 0)
	continue;
      errno = err;
    }
    Dout(dc::warning|dc::system|error_cf, "bind(" << fd << ", " << *bind_addr << ", " << size_of_addr(bind_addr) << ") = -1");
    Dout(dc::system|continued_cf, "close(" << fd << ") = ");
    DEBUG_ONLY(int res =) ::close(fd);
    Dout(dc::finish|cond_error_cf(res == -1), res);
    return false;
  }
  set_bind_addr(bind_addr); // addr should only be set after a successful bind(2)

  Dout(dc::system|continued_cf, "listen(" << fd << ", " << backlog << ") = ");
  int res = ::listen(fd, backlog);
  Dout(dc::finish|cond_error_cf(res == -1), res);
  if (res == -1)
  {
    Dout(dc::system|continued_cf, "close(" << fd << ") = ");
    DEBUG_ONLY(int res2 =) ::close(fd);
    Dout(dc::finish|cond_error_cf(res2 == -1), res2);
    return false;
  }

  init(fd);
  Dout(dc::notice, "Added listen socket " << fd << " at " << *m_bind_addr);
  start();

  return true;
}

void ListenSocketDevice::listen(unsigned short int port, int backlog)
{
  struct sockaddr_in* bind_addr = (struct sockaddr_in*)malloc(sizeof(struct sockaddr_in));
  AllocTag(bind_addr, "struct sockaddr_in " << libcwd::type_info_of(*this).demangled_name() << "::addr");

  bind_addr->sin_family = AF_INET;
  bind_addr->sin_port = htons(port);
  bind_addr->sin_addr.s_addr = INADDR_ANY;

  if (!priv_listen((struct sockaddr*)bind_addr, backlog))
    DoutFatal(dc::core, "ListenSocketDevice::listen(" << port << ", " << backlog << "): failure in setting up listen port!");
}

void ListenSocketDevice::listen(char const* path, int backlog)
{
  struct sockaddr_un* bind_addr;
  bind_addr = (struct sockaddr_un*)malloc(sizeof(bind_addr->sun_family) + strlen(path) + 1);
  AllocTag(bind_addr, "struct sockaddr_un ListenSocketDevice::m_bind_addr");

  bind_addr->sun_family = AF_UNIX;
  strcpy(bind_addr->sun_path, path);

  if (!priv_listen((struct sockaddr*)bind_addr, backlog))
    DoutFatal(dc::core, "ListenSocketDevice::listen(\"" << path << "\", " << backlog << "): failure in setting up UNIX listen socket!");
}

void ListenSocketDevice::read_from_fd(int fd)
{
  int sock_fd;
  socklen_t addrlen = sizeof(struct sockaddr);
  struct sockaddr* accept_addr = (struct sockaddr*)malloc(sizeof(struct sockaddr));
  AllocTag(accept_addr, "struct sockaddr*" << libcwd::type_info_of(*this).demangled_name() << "::accept_addr");

  Dout(dc::system|continued_cf, "accept(" << fd << ", " << accept_addr << ", ");
  if ((sock_fd = accept(fd, accept_addr, &addrlen)) == -1)
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
  Dout(dc::finish, '{' << addrlen << "}) = " << sock_fd);
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
