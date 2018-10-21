// evio -- Event Driven I/O support.
//
//! @file
//! @brief Definition of namespace evio; class SocketAddress.
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
#include "SocketAddress.h"
#include "utils/macros.h"
#include "utils/itoa.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <iostream>
#include <charconv>
#include <cstring>

namespace evio {

std::ostream& operator<<(std::ostream& os, SocketAddress const& socket_address)
{
  return os << socket_address.to_string();
}

std::string SocketAddress::to_string() const
{
  std::string result;
  bool add_brackets = true;
  switch (m_sockaddr.sa_family)
  {
    case AF_INET:
      add_brackets = false;
      /*FALL-THROUGH*/
    case AF_INET6:
    {
      char hostname[42];
      char service[6];
      int err = getnameinfo(&m_sockaddr, sizeof(m_storage), hostname, sizeof(hostname), service, sizeof(service), NI_NUMERICHOST | NI_NUMERICSERV);
      if (err != 0)
        std::cout << "Error: " << gai_strerror(err) << std::endl;
      ASSERT(err == 0);
      result.reserve(48);    // The longest internet address result is "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535"
      if (add_brackets)
        result = '[';
      result += hostname;
      if (add_brackets)
        result += ']';
      result += ':';
      result += service;
      break;
    }
    case AF_UNIX:
      result = m_sockaddr_un_ptr->sun_path;
      break;
    case AF_UNSPEC:
      result = "AF_UNSPEC";
      break;
  }
  return result;
}

void SocketAddress::ptr_qname(arpa_buf_t& arpa_out_buf)
{
  char* buf = arpa_out_buf.data();
  std::array<char, 4> octet_buf;
  switch (m_sockaddr.sa_family)
  {
    case AF_INET:
    {
      struct sockaddr_in& sin(reinterpret_cast<struct sockaddr_in&>(m_sockaddr));
      unsigned long octets = ntohl(sin.sin_addr.s_addr);
      // This writes at most 16 chars to buf.
      for (int i = 0; i < 4; ++i)
      {
        unsigned char val = octets & 0xff;
        char const* p = utils::itoa(octet_buf, val);
        while (*p) *buf++ = *p++;
        *buf++ = '.';
        octets >>= 8;
      }
      // Plus 14 (including the trailing 0) makes 30.
      strcpy(buf, "in-addr.arpa.");
      break;
    }
    case AF_INET6:
    {
      struct sockaddr_in6& sin6(reinterpret_cast<struct sockaddr_in6&>(m_sockaddr));
      static char const hexdigit[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
      // This writes 64 chars to buf.
      for (int i = 15; i >= 0; --i)
      {
        unsigned int nyble = sin6.sin6_addr.s6_addr[i];
        for (int j = 0; j < 2; ++j)
        {
          *buf++ = hexdigit[0xf & nyble];
          *buf++ = '.';
          nyble >>= 4;
        }
      }
      // Plus 10 (including the trailing 0) makes 74.
      strcpy(buf, "ip6.arpa.");
      break;
    }
    default:
      DoutFatal(dc::fatal, "SocketAddress::ptr_qname called for " << *this << ", which isn't an IP address.");
  }
}

namespace {

// Decode a string of the form ddd.ddd.ddd.ddd and return its length.
//                          i = 0   1   2   3
// The result is written to addr in network order (most significant octet first).
// addr must be an array of at least four bytes.
int decode_ipv4_address(std::string_view sv, uint8_t* addr)
{
  char const* p = sv.data();
  char const* const end = p + sv.size();
  int i = 0;
  for (;;)
  {
    std::from_chars_result result = std::from_chars(p, end, addr[i]);
    ASSERT(result.ec == std::errc());
    p = result.ptr;
    if (++i == 4)       // In this case result.ptr can point to anything.
      break;
    ASSERT(p < end && *p == '.');
    ++p;
  }
  return p - sv.data();
}

int decode_ip_address(std::string_view sv, sa_family_t& family, uint8_t* addr)
{
  int len = 0;
  int saw_double_colon = -1;                    // Set to i for the first byte after a double colon; or -1 is there is no double colon (yet).
  bool saw_colon = sv.front() == ':';
  if (saw_colon)
  {
    ASSERT(family != AF_INET && sv.size() > 2 && sv[1] == ':');      // An IPv6 address can only start with a colon if that is a double colon.
    sv.remove_prefix(2);                        // Eat the leading double colon.
    saw_double_colon = 0;
    len = 2;
  }
  char const* p = sv.data();
  char const* const end = sv.data() + sv.size();
  int i = 0;                                    // Index into addr.
  while (p < end && *p != ']')
  {
    uint16_t hextet;
    std::from_chars_result result = std::from_chars(p, end, hextet, 16);
    ASSERT(result.ec == std::errc());
    // hextet was *just* initialized.
PRAGMA_DIAGNOSTIC_PUSH_IGNORE_maybe_uninitialized
    addr[i] = hextet >> 8;
    addr[i + 1] = hextet & 0xff;
PRAGMA_DIAGNOSTIC_POP
    i += 2;
    if (i == 16 || result.ptr == end || *result.ptr == ']')
    {
      p = result.ptr;
      break;
    }
    ASSERT(family != AF_INET || *result.ptr == '.');
    if (*result.ptr == '.')
    {
      i -= 2;
      if (saw_colon)    // IPv6?
      {
        ASSERT(saw_double_colon == 0 && i == 2 && addr[0] == 0xff && addr[1] == 0xff);    // IPv4 mapping only allowed after ::ffff:
        sv.remove_prefix(5);      // Skip over the 'ffff:'.
        len += 5;
      }
      else if (family == AF_INET6)
      {
        // Prepend with ::ffff:.
        saw_colon = true;
        saw_double_colon = 0;
        addr[0] = addr[1] = 0xff;
        i = 2;
      }
      p += decode_ipv4_address(sv, addr + i);
      i += 4;
      break;
    }
    p = result.ptr;
    ASSERT(*p == ':');
    saw_colon = true;
    ++p;
    if (AI_UNLIKELY(*p == ':'))
    {
      saw_double_colon = i;
      ++p;
    }
  }
  len += p - sv.data();
  family = saw_colon ? AF_INET6 : AF_INET;
  if (saw_colon)
  {
    ASSERT(i == 16 || saw_double_colon != -1);
    int offset = 16 - i;
    if (offset > 0)
    {
      int j = 15;
      for (; j >= saw_double_colon + offset; --j)
        addr[j] = addr[j - offset];
      for (; j >= saw_double_colon; --j)
        addr[j] = 0;
    }
  }
  return len;
}

// Convert the decimal port number in the range [0, 65535] in sv to in_port using network order.
// Returns the number of characters processed.
int decode_port(std::string_view const sv, in_port_t& in_port)
{
  uint16_t port;
  std::from_chars_result result = std::from_chars(sv.data(), sv.data() + sv.size(), port);
  ASSERT(result.ec == std::errc());
  in_port = ntohs(port);
  return result.ptr - sv.data();
}

} // namespace

void SocketAddress::make_sockaddr_un(std::string_view sockaddr_text)
{
  // These two must be set atomically, but that will be the case
  // since this function is only called from constructors.
  m_sockaddr.sa_family = AF_UNIX;
  m_sockaddr_un_ptr = new struct sockaddr_un;

  // Make sure that sun_path is always null terminated and not too long,
  // so that all other code can rely on this.
  size_t len = sockaddr_text.size();
  ASSERT(len < sizeof(m_sockaddr_un_ptr->sun_path));
  std::memcpy(m_sockaddr_un_ptr->sun_path, sockaddr_text.data(), len);
  m_sockaddr_un_ptr->sun_path[len] = '\0';
  m_sockaddr_un_ptr->sun_family = AF_UNIX;
}

void SocketAddress::deinit()
{
  if (m_sockaddr.sa_family == AF_UNIX)
    delete m_sockaddr_un_ptr;
  Debug(m_sockaddr_un_ptr = nullptr);
}

// Possible formats:
//
// /some/full/path
// ddd.ddd.ddd.ddd:ppppp (optional brackets around ddd.ddd.ddd.ddd, but not recommended).
// [hhhh:hhhh:hhhh:hhhh:hhhh:hhhh:hhhh:hhhh]:ppppp
// [::ffff:ddd.ddd.ddd.ddd]:ppppp (the brackets are optional in this case).
void SocketAddress::decode_sockaddr(std::string_view sockaddr_text, unsigned short sa_family, int port)
{
  // Don't call this function with an empty sockaddr_text.
  ASSERT(!sockaddr_text.empty());
  char first = sockaddr_text.front();
  if (AI_UNLIKELY(sa_family == AF_UNIX || first == '/'))
  {
    // Don't pass a port or a family other than AF_UNIX with a unix socket.
    ASSERT((sa_family == AF_UNIX || sa_family == AF_UNSPEC) && port == -1);
    make_sockaddr_un(sockaddr_text);
    return;
  }
  // Always allow brackets around the IP#.
  bool has_brackets = first == '[';
  if (has_brackets)
    sockaddr_text.remove_prefix(1);
  m_sockaddr.sa_family = sa_family;
  uint8_t addr[16];
  size_t len = decode_ip_address(sockaddr_text, m_sockaddr.sa_family, addr);
  if (has_brackets)
  {
    // The matching closing bracket must be present.
    ASSERT(len < sockaddr_text.size() && sockaddr_text[len] == ']');
    ++len;
  }
  in_port_t in_port;
  if (port == -1)
  {
    // The port number must be separated by a colon.
    ASSERT(len < sockaddr_text.size() && sockaddr_text[len] == ':');
    sockaddr_text.remove_prefix(len + 1);
    len = decode_port(sockaddr_text, in_port);
  }
  else
    in_port = ntohs(port);
  // Don't supply trailing characters.
  ASSERT(len == sockaddr_text.size());

  // Copy the decoded data to the appropriate place.
  if (m_sockaddr.sa_family == AF_INET)
  {
    struct sockaddr_in& sin(reinterpret_cast<struct sockaddr_in&>(m_sockaddr));
    sin.sin_port = in_port;
    std::memcpy(&sin.sin_addr, &addr, sizeof(sin.sin_addr));
  }
  else
  {
    struct sockaddr_in6& sin6(reinterpret_cast<struct sockaddr_in6&>(m_sockaddr));
    sin6.sin6_port = in_port;
    std::memcpy(&sin6.sin6_addr, &addr, sizeof(sin6.sin6_addr));
    // FIXME: What to set these two to?
    sin6.sin6_flowinfo = 0;
    sin6.sin6_scope_id = 0;
  }
}

void SocketAddress::move(SocketAddress&& other)
{
  struct sockaddr const* ptr = &other.m_sockaddr;
  switch (ptr->sa_family)
  {
    case AF_INET:
      std::memcpy(&m_sockaddr, ptr, sizeof(struct sockaddr_in));
      break;
    case AF_INET6:
      std::memcpy(&m_sockaddr, ptr, sizeof(struct sockaddr_in6));
      break;
    case AF_UNIX:
      m_sockaddr.sa_family = AF_UNIX;
      m_sockaddr_un_ptr = other.m_sockaddr_un_ptr;
      break;
    default:
      DoutFatal(dc::core, "SocketAddress::move(SocketAddress&& other): sa_family is not AF_INET, AF_INET6 or AF_UNIX.");
  }
  other.m_sockaddr.sa_family = AF_UNSPEC;
}

void SocketAddress::init(struct sockaddr const* sa_addr)
{
  switch (sa_addr->sa_family)
  {
    case AF_INET:
      std::memcpy(&m_sockaddr, sa_addr, sizeof(struct sockaddr_in));
      break;
    case AF_INET6:
      std::memcpy(&m_sockaddr, sa_addr, sizeof(struct sockaddr_in6));
      break;
    case AF_UNIX:
    {
      struct sockaddr_un const* sun(reinterpret_cast<struct sockaddr_un const*>(sa_addr));
      make_sockaddr_un(std::string_view(sun->sun_path, strlen(sun->sun_path)));
      break;
    }
    default:
      DoutFatal(dc::core, "SocketAddress::init(struct sockaddr const*): sa_family is not AF_INET, AF_INET6 or AF_UNIX.");
  }
}

// Return true if a compare with sa equals val, where
// the meaning of val is: -1 : less than, 0 : equal to, 1 : greater than.
bool SocketAddress::compare_with(SocketAddress const& sa, int val) const
{
  int res;
  if (m_sockaddr.sa_family != sa.m_sockaddr.sa_family)
  {
    res = (m_sockaddr.sa_family < sa.m_sockaddr.sa_family) ? -1 : 1;
  }
  else
  {
    switch (m_sockaddr.sa_family)
    {
      case AF_INET:
        res = std::memcmp(&m_sockaddr, &sa.m_sockaddr, sizeof(struct sockaddr_in));
        break;
      case AF_INET6:
        res = std::memcmp(&m_sockaddr, &sa.m_sockaddr, sizeof(struct sockaddr_in6));
        break;
      case AF_UNIX:
        res = strcmp(m_sockaddr_un_ptr->sun_path, sa.m_sockaddr_un_ptr->sun_path);
        break;
      default:
        return false;
    }
  }
  return res == val;
}

} // namespace evio
