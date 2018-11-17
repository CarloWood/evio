// evio -- Event Driven I/O support.
//
//! @file
//! @brief Definition of inet utility functions.
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
#include "inet_support.h"
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

char const* strherror(int herrno)
{
  switch(herrno)
  {
    case HOST_NOT_FOUND:
      return "Unknown host";
    case TRY_AGAIN:
      return "Host name lookup failure";
    case NO_RECOVERY:
      return "Unknown server error";
    case NO_DATA:
      return "No address associated with name";
  }
  return "Value of `herror' out of range";
}

void set_rcvsockbuf(int sock_fd, size_t rcvbuf_size, size_t minimum_size)
{
  int opt = rcvbuf_size;
  if (opt == 0)
  {
    // FIXME: this heuristic makes little sense.
    // See http://www.masterraghu.com/subjects/np/introduction/unix_network_programming_v1.3/ch02lev1sec11.html for information about this subject.
    opt = utils::nearest_power_of_two(2 * minimum_size + 256);
    if (opt < 8192)
      opt = 8192;
  }
  Dout(dc::warning(!utils::is_power_of_two(opt)), "set_rcvsockbuf: socket receive buffer is not a power of two!");
  Dout(dc::notice, "Setting receive buffer size for socket " << sock_fd << " to " << opt << " bytes.");
  if (setsockopt(sock_fd, SOL_SOCKET, SO_RCVBUF, (optval_t)&opt, sizeof(opt)) < 0)
  {
    THROW_ALERTE("setsockopt([FD], SOL_SOCKET, SO_RCVBUF, [[OPT]], [SIZE]) = -1",
        AIArgs("[FD]", sock_fd)("[OPT]", opt)("[SIZE]", sizeof(opt)));
  }
}

void set_sndsockbuf(int sock_fd, size_t sndbuf_size, size_t minimum_size)
{
  int opt = sndbuf_size;
  if (opt == 0)
  {
    opt = utils::nearest_power_of_two(minimum_size);
    if (opt < 8192)
      opt = 8192;
  }
  Dout(dc::warning(!utils::is_power_of_two(opt)), "set_sndsockbuf: socket send buffer is not a power of two!");
  Dout(dc::notice, "Setting send buffer size for socket " << sock_fd << " to " << opt << " bytes.");
  if (setsockopt(sock_fd, SOL_SOCKET, SO_SNDBUF, (optval_t)&opt, sizeof(opt)) < 0)
  {
    THROW_ALERTE("setsockopt([FD], SOL_SOCKET, SO_SNDBUF, [[OPT]], [SIZE]) = -1",
        AIArgs("[FD]", sock_fd)("[OPT]", opt)("[SIZE]", sizeof(opt)));
  }
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
