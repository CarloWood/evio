/**
 * evio -- A cwm4 git submodule for adding support for buffered, iostream oriented, epoll based I/O.
 *
 * @file
 * @brief Definition of inet utility functions.
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

#include "sys.h"
#include "inet_support.h"
#include "SocketAddress.h"
#include "utils/nearest_power_of_two.h"
#include "utils/is_power_of_two.h"
#include "utils/AIAlert.h"
#include <netdb.h>		// Needed for struct hostent
#include <netinet/in.h>
#include <sys/socket.h>		// Needed for AF_INET
#include <sys/un.h>
#include <fcntl.h>
#include <sstream>
#include <arpa/inet.h>          // Needed for inet_ntop

#include "debug.h"
#ifdef CWDEBUG
#include <libcwd/buf2str.h>
#endif

using namespace std;

namespace evio {

using optval_t = void*;

int print_hostent_on(struct hostent const* h, ostream& o)
{
  o << "The official name of the host: \"" << h->h_name << "\"\n";
  if (h->h_aliases[0])
    o << "Aliases:\n";
  else
    o << "No aliases.\n";
  for (int c = 0; h->h_aliases[c]; ++c)
    o << '\"' << h->h_aliases[c] << "\"\n";
  if (h->h_addrtype != AF_INET && h->h_addrtype != AF_INET6)
  {
    o << flush;
    Dout( dc::warning, "Returned address type is not AF_INET or AF_INET6!?" );
    return -1;
  }
  o << "Address length in bytes: " << h->h_length << endl;
  if (h->h_addr_list[0])
    o << "Network addresses:\n";
  else
    o << "No network addresses.\n";
  char buf[INET6_ADDRSTRLEN];
  for (int c = 0; h->h_addr_list[c]; ++c)
    o << '\"' << inet_ntop(h->h_addrtype, (struct in_addr*)h->h_addr_list[c], buf, sizeof(buf)) << "\"\n";
  return 0;
}

// Without setting a socket buffer size, the buffers are HUGE (by default).
// This is bad because
// 1) we already do the buffering and we're doing it better.
// 2) huge buffers just cause latency; they kill the flow control that this library tries to achieve.
//
// For best flow control, the send and receive buffers should roughly equal to the minimum block size:
// Under normal circumstances the buffer really shouldn't grow larger than one block (the minimum
// block size) and even when it does, then the second block has the same size. Hence, the largest
// amount that we try to write to a socket is usually the minimum block size (nl. until the buffer runs
// really full-- but then things are wrong already anyway; a low watermark should help to control
// that size). If the socket send buffer is empty then it is not needed to be larger than this
// size; however, data is sent to the peer in MTU sized packets, existing of Maximum Segment Size (MSS)
// sized data segments (extracted from the socket send buffer) plus a 40 byte header
// (e.g. see https://searchnetworking.techtarget.com/definition/maximum-segment-size).
// For example, with an MTU of 1500 bytes, MMS will be 1500 - 40 = 1460 bytes. Those segments are
// kept in the socket sndbuf until the peer has acknowledged them. So, until that happens there is
// less room in the socket buffer and we might not be able to write all of the minimum block size
// to the socket send buffer. This is not a problem, as long as there are enough segments available
// in the socket send buffer to be sent without getting a stall on to-be-acknowledged packets.
//
// In other words, the socket send buffer is a trade off between latency and data transfer speed,
// both of which can be measured; the only real way to determine the best SO_SNDBUF size.
//
// The SO_RCVBUF size allows for flow control of received data. If our application can not process
// incoming data fast enough data will pile up in our input buffer, causing latency on top of the
// (maximum (slow?) speed). Picking a smallish input buffer, the input buffer will run full causing
// the library to stop reading the socket, in turn causing the socket receive buffer to run full
// which, using TCP window adjustment mechanism, will tell the sender to slow down.  Also the sender
// shouldn't use a large (socket send) buffer of course, or there will still be latency.
//
// If the socket receive buffer is ridiculously large (as is the default) then that will just fill
// up and we can read at our leasure. This is not bad when we don't care about latency; for example
// when we just want to download data one-way; but when latency matters then the socket receive buffer
// should be as small as possible without causing dramatic transfer speed reduction for the case
// where our application CAN easily keep up with processing the incoming data.
//
// See http://www.masterraghu.com/subjects/np/introduction/unix_network_programming_v1.3/ch02lev1sec11.html
// and "SO_RCVBUF and SO_SNDBUF Socket Options" on
// http://www.masterraghu.com/subjects/np/introduction/unix_network_programming_v1.3/ch07lev1sec5.html#ch07lev1sec5
// for detailed information about the subject of socket buffers.

void set_rcvsockbuf(int sock_fd, size_t rcvbuf_size, size_t minimum_block_size)
{
  // The smaller the slower - smaller than this seems just ridiculous (the default is like 512 kB).
  constexpr int rcvbuf_limit = 4096;        // Sanity.
  int opt = rcvbuf_size;
  if (opt == 0)
  {
    // Either pass rcvbuf_size or minimum_block_size (or both in which case rcvbuf_size will be used).
    ASSERT(minimum_block_size != 0);
    opt = minimum_block_size;
    if (opt < rcvbuf_limit)
      opt = rcvbuf_limit;
  }
  Dout(dc::notice, "Setting receive buffer size for socket " << sock_fd << " to " << opt << " bytes.");
#ifdef CWDEBUG
  int optin = opt;
#endif
  int ret = setsockopt(sock_fd, SOL_SOCKET, SO_RCVBUF, (optval_t)&opt, sizeof(opt));
  Dout(dc::system|cond_error_cf(ret == -1), "setsockopt(" << sock_fd << ", SOL_SOCKET, SO_RCVBUF, {" << optin << "}, " << sizeof(opt) << ") = " << ret);
  if (ret == -1)
  {
    THROW_ALERTE("setsockopt([FD], SOL_SOCKET, SO_RCVBUF, [[OPT]], [SIZE]) = -1",
        AIArgs("[FD]", sock_fd)("[OPT]", opt)("[SIZE]", sizeof(opt)));
  }
  Dout(dc::warning(optin < std::max(rcvbuf_limit, (int)minimum_block_size)),
      "Requested SO_SNDBUF is less than " << ((optin < rcvbuf_limit) ? std::to_string(rcvbuf_limit).c_str() : "the minimum block size") << "; you better know what you are doing.");
}

void set_sndsockbuf(int sock_fd, size_t sndbuf_size, size_t minimum_block_size)
{
  // Emperically determined to be the minimum sndbuf of a socket that can communicate with a socket (over localhost) with default socket buffer sizes.
  // A smaller value leads to strange stalls in epoll_pwait() of ~43 ms per call. Also see src/epoll_bug.c in ai-evio-testsuite.
  constexpr int sndbuf_limit = 33182;
  int opt = sndbuf_size;
  if (opt == 0)
  {
    // Either pass sndbuf_size or minimum_block_size (or both in which case sndbuf_size will be used).
    ASSERT(minimum_block_size != 0);
    opt = minimum_block_size;
    if (opt < sndbuf_limit)
      opt = sndbuf_limit;
  }
  Dout(dc::notice, "Setting send buffer size for socket " << sock_fd << " to " << opt << " bytes.");
#ifdef CWDEBUG
  int optin = opt;
#endif
  int ret = setsockopt(sock_fd, SOL_SOCKET, SO_SNDBUF, (optval_t)&opt, sizeof(opt));
  Dout(dc::system|cond_error_cf(ret == -1), "setsockopt(" << sock_fd << ", SOL_SOCKET, SO_SNDBUF, {" << optin << "}, " << sizeof(opt) << ") = " << ret);
  if (ret == -1)
  {
    THROW_ALERTE("setsockopt([FD], SOL_SOCKET, SO_SNDBUF, [[OPT]], [SIZE]) = -1",
        AIArgs("[FD]", sock_fd)("[OPT]", opt)("[SIZE]", sizeof(opt)));
  }
  Dout(dc::warning(optin < std::max(sndbuf_limit, (int)minimum_block_size)),
      "Requested SO_SNDBUF is less than " << ((optin < sndbuf_limit) ? std::to_string(sndbuf_limit).c_str() : "the minimum block size") << "; you better know what you are doing.");
}

void set_sock_buffers(int fd, size_t input_minimum_block_size, size_t output_minimum_block_size, size_t rcvbuf_size, size_t sndbuf_size)
{
  try
  {
    set_rcvsockbuf(fd, rcvbuf_size, input_minimum_block_size);
    set_sndsockbuf(fd, sndbuf_size, output_minimum_block_size);
  }
  catch (AIAlert::Error const& error)
  {
    Dout(dc::system|continued_cf, "close(" << fd << ") = ");
    CWDEBUG_ONLY(int ret =) ::close(fd);
    Dout(dc::finish|cond_error_cf(ret == -1), ret);
    THROW_ALERT("Socket::set_sock_buffers([FD], [INMINBLOCKSZ], [OUTMINBLOCKSZ], [RCVBUF_SIZE], [SNDBUF_SIZE]):",
        AIArgs("[FD]", fd)("INMINBLOCKSZ", input_minimum_block_size)("OUTMINBLOCKSZ", output_minimum_block_size)
              ("[RCVBUF_SIZE]", rcvbuf_size)("[SNDBUF_SIZE]", sndbuf_size),
        error);
  }
}

// On success, returns the file descriptor of a new socket, with socket buffers
// rcvbuf_size and sndbuf_size, that was bound to if_address and connected to remote_address.
// On failure -1 is returned.
int create_tcp_connection(SocketAddress const& remote_address, size_t input_minimum_block_size, size_t output_minimum_block_size, size_t rcvbuf_size, size_t sndbuf_size, SocketAddress const& if_address)
{
  // The address to connect needs to make sense.
  ASSERT(!remote_address.is_unspecified());

  Dout(dc::system|continued_cf, "socket(" << remote_address.family() << ", SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0) = ");
  int fd = ::socket(remote_address.family(), SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  Dout(dc::finish|cond_error_cf(fd < 0), fd);
  if (fd < 0)
    return -1;

  // Send and receive buffer sizes must be set before calling connect().
  if (remote_address.is_ip())
  {
    set_sock_buffers(fd, input_minimum_block_size, output_minimum_block_size, rcvbuf_size, sndbuf_size);
  }

  if (!if_address.is_unspecified())
  {
    Dout(dc::system|continued_cf, "bind(" << fd << ", " << if_address << ", " << size_of_addr(if_address) << ") = ");
    int ret = ::bind(fd, if_address, size_of_addr(if_address));
    if (ret < 0)
    {
      Dout(dc::finish|error_cf, ret);
      Dout(dc::warning|error_cf, "bind: " << if_address);
      Dout(dc::system|continued_cf, "close(" << fd << ") = ");
      CWDEBUG_ONLY(ret =) ::close(fd);
      Dout(dc::finish|cond_error_cf(ret < 0), ret);
      return -1;
    }
    Dout(dc::finish|cond_error_cf(ret < 0), ret);
  }

  Dout(dc::system|continued_cf, "connect(" << fd << ", " << remote_address << ", " << size_of_addr(remote_address) << ") = ");
  int ret = ::connect(fd, remote_address, size_of_addr(remote_address));
  if (ret < 0 && errno != EINPROGRESS)
  {
    Dout(dc::finish|error_cf, ret);
    Dout(dc::system|continued_cf, "close(" << fd << ") = ");
    CWDEBUG_ONLY(ret =) ::close(fd);
    Dout(dc::finish|cond_error_cf(ret < 0), ret);
    return -1;
  }
  Dout(dc::finish|cond_error_cf(ret < 0), ret);
  return fd;
}

size_t size_of_addr(struct sockaddr const* addr)
{
  switch(addr->sa_family)
  {
    case AF_INET:
      return sizeof(struct sockaddr_in);
    case AF_INET6:
      return sizeof(struct sockaddr_in6);
    case AF_UNIX:
      return sizeof(struct sockaddr_un);
    default:
      DoutFatal(dc::core, "size_of_addr: Unsupported Adress Family type");
  }
}

} // namespace evio

ostream& operator<<(ostream& os, struct in_addr const& in)
{
  char buf[INET_ADDRSTRLEN];
  os << inet_ntop(AF_INET, &in, buf, sizeof(buf));
  return os;
}

std::ostream& operator<<(std::ostream& os, struct in6_addr const& in6)
{
  char buf[INET6_ADDRSTRLEN];
  os << inet_ntop(AF_INET6, &in6, buf, sizeof(buf));
  return os;
}

#if 0   // Use SocketAddress

ostream& operator<<(ostream& os, struct sockaddr_in const& s)
{
  os << s.sin_addr << " port " << ntohs(s.sin_port);
  return os;
}

ostream& operator<<(ostream& os, struct sockaddr_un const& s)
{
  os << '\"';
  if (*s.sun_path)
    os << s.sun_path;
  else
    os << "<unknown>";
  os << '\"';
  return os;
}

ostream& operator<<(ostream& os, struct sockaddr const& s)
{
  switch (s.sa_family)
  {
    case AF_INET:
      os << *(struct sockaddr_in*)&s;
      break;
    case AF_UNIX:
      os << *(struct sockaddr_un*)&s;
      break;
    default:
      os << "<unknown address family (" << s.sa_family << ")>";
#ifdef CWDEBUG
      os << " : " << libcwd::buf2str(s.sa_data, sizeof(s.sa_data));
#endif
      break;
  }
  return os;
};

#endif
