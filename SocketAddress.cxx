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
#include "utils/AIAlert.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <iostream>
#include <charconv>
#include <cstring>

namespace evio {

struct gai_error_codes
{
  int mCode;

  gai_error_codes(int code) : mCode(code) { }
  operator int() const { return mCode; }
};

std::error_code make_error_code(gai_error_codes);

} // namespace evio

// Register evio::gai_error_codes as valid error code.
namespace std {

template<> struct is_error_code_enum<evio::gai_error_codes> : true_type { };

} // namespace std

namespace evio {

std::ostream& operator<<(std::ostream& os, SocketAddress const& socket_address)
{
  return os << socket_address.to_string();
}

std::string SocketAddress::to_string(bool no_port) const
{
  std::string result;
  bool add_brackets = !no_port;
  switch (m_sockaddr.sa_family)
  {
    case AF_INET:
      add_brackets = false;
      /*FALL-THROUGH*/
    case AF_INET6:
    {
      char hostname[42];
      char service[6];
      gai_error_codes err = getnameinfo(&m_sockaddr, sizeof(m_storage), hostname, sizeof(hostname), service, sizeof(service), NI_NUMERICHOST | NI_NUMERICSERV);
      if (err)
        THROW_FALERTC(err, "getnameinfo");
      result.reserve(48);    // The longest internet address result is "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535"
      if (add_brackets)
        result = '[';
      result += hostname;
      if (add_brackets)
        result += ']';
      if (!no_port)
      {
        result += ':';
        result += service;
      }
      break;
    }
    case AF_UNIX:
      result = m_sockaddr_un_ptr->sun_path;
      break;
    case AF_UNSPEC:
      result = "AF_UNSPEC";
      break;
    case AF_PACKET:
      result = "AF_PACKET";
      break;
    default:
      result = "AF_unknown";
      break;
  }
  return result;
}

void SocketAddress::ptr_qname(arpa_buf_t& arpa_out_buf) const
{
  char* buf = arpa_out_buf.data();
  std::array<char, 4> octet_buf;
  switch (m_sockaddr.sa_family)
  {
    case AF_INET:
    {
      struct sockaddr_in const& sin(reinterpret_cast<struct sockaddr_in const&>(m_sockaddr));
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
      struct sockaddr_in6 const& sin6(reinterpret_cast<struct sockaddr_in6 const&>(m_sockaddr));
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
      DoutFatal(dc::fatal|flush_cf, "SocketAddress::ptr_qname called for " << *this << ", which isn't an IP address.");
  }
}

namespace {

// Decode a string of the form ddd.ddd.ddd.ddd and return its length.
//                          i = 0   1   2   3
// The result is written to addr in network order (most significant octet first).
// addr must be an array of at least four bytes.
int decode_ipv4_address(std::string_view ipv4_str, uint8_t* addr)
{
  char const* p = ipv4_str.data();
  char const* const end = p + ipv4_str.size();
  int i = 0;
  for (;;)
  {
    std::from_chars_result result = std::from_chars(p, end, addr[i]);
    if (AI_UNLIKELY(result.ec != std::errc()))
      THROW_ALERTC(result.ec,
          "decode_ipv4_address: \"[IPV4_STR]\": octet at \"[OCTET_STR]\"",
          AIArgs("[IPV4_STR]",  ipv4_str)
                ("[OCTET_STR]", std::string_view(p, end - p)));
    p = result.ptr;
    if (++i == 4)       // In this case result.ptr can point to anything.
      break;
    if (AI_UNLIKELY(p == end || *p != '.'))
      THROW_ALERT("decode_ipv4_address: \"[IPV4_STR]\": expected period.", AIArgs("[IPV4_STR]", ipv4_str));
    ++p;
  }
  return p - ipv4_str.data();
}

int decode_ip_address(std::string_view ip_number_str, sa_family_t& family, uint8_t* addr)
{
  std::string_view orig_ip_number_str(ip_number_str);
  int len = 0;
  int saw_double_colon = -1;                    // Set to i for the first byte after a double colon; or -1 is there is no double colon (yet).
  bool saw_colon = ip_number_str.front() == ':';
  if (saw_colon)
  {
    if (AI_UNLIKELY(!(family != AF_INET && ip_number_str.size() > 2 && ip_number_str[1] == ':')))
    {
      THROW_ALERT((family == AF_INET)
          ? "decode_ip_address: \"[IP_NUMBER_STR]\": IPv4 can not start with a colon."
          : "decode_ip_address: \"[IP_NUMBER_STR]\": IPv6 can only start with a colon if that is a double colon.",
          AIArgs("[IP_NUMBER_STR]", orig_ip_number_str));
    }
    ip_number_str.remove_prefix(2);                        // Eat the leading double colon.
    saw_double_colon = 0;
    len = 2;
  }
  char const* p = ip_number_str.data();
  char const* const end = ip_number_str.data() + ip_number_str.size();
  int saw_non_zero = -1;
  int i = 0;                                    // Index into addr.
  while (p < end && *p != ']')
  {
    uint16_t hextet;
    std::from_chars_result result = std::from_chars(p, end, hextet, 16);
    if (AI_UNLIKELY(result.ec != std::errc()))
    {
      THROW_ALERT("decode_ip_address: \"[IP_NUMBER_STR]\": std::from_chars failed for \"[HEXTET]\": [ERROR_MSG].",
          AIArgs("[IP_NUMBER_STR]", orig_ip_number_str)
                ("[HEXTET]",        std::string_view(p, end - p))
                ("[ERROR_MSG]",     make_error_code(result.ec).message()));
    }
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
    if (AI_UNLIKELY(family == AF_INET && *result.ptr != '.'))
    {
      THROW_ALERT("decode_ip_address: \"[IP_NUMBER_STR]\": IPv4 parse error; expected a period at \"[PTR]\".",
          AIArgs("[IP_NUMBER_STR]", orig_ip_number_str)
                ("[PTR]", result.ptr));
    }
    if (*result.ptr == '.')
    {
      i -= 2;
      if (saw_colon)    // IPv6?
      {
        if (AI_UNLIKELY(saw_non_zero == 1))
        {
          THROW_ALERT("decode_ip_address: \"[IP_NUMBER_STR]\": IPv4 mapping only allowed after \"::\" or \"::ffff:\".",
              AIArgs("[IP_NUMBER_STR]", orig_ip_number_str));
        }
        int cur = p - ip_number_str.data();
        ip_number_str.remove_prefix(cur);      // Skip to start of IPv4 address.
        len += cur;
      }
      else if (family == AF_INET6)
      {
        // Prepend with ::ffff:.
        saw_colon = true;
        saw_double_colon = 0;
        addr[0] = addr[1] = 0xff;
        i = 2;
      }
      try
      {
        p += decode_ipv4_address(ip_number_str, addr + i);
      }
      catch (AIAlert::Error const& error)
      {
        THROW_ALERT("decode_ip_address: \"[IP_NUMBER_STR]\": ",
            AIArgs("[IP_NUMBER_STR]", orig_ip_number_str),
            error);
      }
      i += 4;
      break;
    }
    if (hextet > 0)
    {
      if (saw_non_zero == -1 && hextet == 0xffff)
        saw_non_zero = 0;
      else
        saw_non_zero = 1;
    }
    p = result.ptr;
    if (AI_UNLIKELY(*p != ':'))
      THROW_ALERT("decode_ip_address: \"[IP_NUMBER_STR]\": expected ':' at \"[PTR]\"",
          AIArgs("[IP_NUMBER_STR]", orig_ip_number_str)
                ("[PTR]", p));
    saw_colon = true;
    ++p;
    if (AI_UNLIKELY(*p == ':'))
    {
      if (saw_double_colon != -1)
        THROW_ALERT("decode_ip_address: \"[IP_NUMBER_STR]\": a double colon is only allowed once.",
            AIArgs("[IP_NUMBER_STR]", orig_ip_number_str));
      saw_double_colon = i;
      if (saw_non_zero == 0)
        saw_non_zero = 1;
      ++p;
    }
  }
  len += p - ip_number_str.data();
  family = saw_colon ? AF_INET6 : AF_INET;
  if (saw_colon)
  {
    if (AI_UNLIKELY(i != 16 && saw_double_colon == -1))
      THROW_ALERT("decode_ip_address: \"[IP_NUMBER_STR]\": not enough hextets and no '::'",
          AIArgs("[IP_NUMBER_STR]", orig_ip_number_str));
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
  // Note: sv must be numeric port (in string form). Not a service name.
  // Throw if there wasn't any digit, or if the result doesn't fit in a uint16_t.
  if (AI_UNLIKELY(result.ec != std::errc()))
    THROW_ALERTC(result.ec, "decode_port: \"[PORT]\"", AIArgs("[PORT]", sv));
  in_port = htons(port);
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
  if (AI_UNLIKELY(len >= sizeof(m_sockaddr_un_ptr->sun_path)))
    THROW_FALERTC(SocketAddress_make_sockaddr_un_path_too_long, "\"[SOCKADDR_TEXT]\": UNIX socket path is too long");
  std::memcpy(m_sockaddr_un_ptr->sun_path, sockaddr_text.data(), len);
  m_sockaddr_un_ptr->sun_path[len] = '\0';
  m_sockaddr_un_ptr->sun_family = AF_UNIX;
}

void SocketAddress::deinit()
{
  // This private function is only called immediately before a re-initialization
  // and therefore only needs to take care of freeing m_sockaddr_un_ptr.
  if (m_sockaddr.sa_family == AF_UNIX)
  {
    delete m_sockaddr_un_ptr;
    m_sockaddr_un_ptr = nullptr;
  }
  Debug(m_sockaddr_un_ptr = nullptr);
}

// Possible formats:
//
// /some/full/path
// ddd.ddd.ddd.ddd:ppppp (optional brackets around ddd.ddd.ddd.ddd, but not recommended).
// [hhhh:hhhh:hhhh:hhhh:hhhh:hhhh:hhhh:hhhh]:ppppp
// [::ffff:ddd.ddd.ddd.ddd]:ppppp (the brackets are optional in this case).
void SocketAddress::decode_sockaddr(std::string_view sockaddr_text, sa_family_t sa_family, int port_h)
{
  // Don't call this function with an empty sockaddr_text.
  ASSERT(!sockaddr_text.empty());
  char first = sockaddr_text.front();
  if (AI_UNLIKELY(sa_family == AF_UNIX || first == '/'))
  {
    // Don't pass a port or a family other than AF_UNIX with a unix socket.
    if ((sa_family != AF_UNIX && sa_family != AF_UNSPEC) || port_h != -1)
    {
      THROW_ALERTC(SocketAddress_decode_sockaddr_parse_error,
          "\"[SOCKADDR_TEXT]\": is a UNIX socket, but IP address expected because sa_family = [FAMILY] and port_h = [PORT]",
          AIArgs("[SOCKADDR_TEXT]", sockaddr_text)("FAMILY]", sa_family)("[PORT]", port_h));
    }
    make_sockaddr_un(sockaddr_text);
    return;
  }
  // Always allow brackets around the IP#.
  std::string_view orig_sockaddr_text(sockaddr_text);
  bool has_brackets = first == '[';
  if (has_brackets)
    sockaddr_text.remove_prefix(1);
  m_sockaddr.sa_family = sa_family;
  uint8_t addr[16];
  size_t len;
  try
  {
    len = decode_ip_address(sockaddr_text, m_sockaddr.sa_family, addr);
  }
  catch (AIAlert::Error const& error)
  {
    THROW_ALERTC(SocketAddress_decode_sockaddr_parse_error,
        "\"[SOCKADDR_TEXT]\": ",
        AIArgs("[SOCKADDR_TEXT]", orig_sockaddr_text),
        error);
  }
  if (has_brackets)
  {
    // The matching closing bracket must be present.
    if (AI_UNLIKELY(len == sockaddr_text.size() || sockaddr_text[len] != ']'))
    {
      THROW_ALERTC(SocketAddress_decode_sockaddr_parse_error,
          "\"[SOCKADDR_TEXT]\": missing ']'",
          AIArgs("[SOCKADDR_TEXT]", orig_sockaddr_text));
    }
    ++len;
  }
  in_port_t in_port;
  if (port_h == -1)
  {
    // The port number must be separated by a colon.
    if (AI_UNLIKELY(len == sockaddr_text.size()))
    {
      THROW_ALERTC(SocketAddress_decode_sockaddr_parse_error,
          "\"[SOCKADDR_TEXT]\": missing trailing \":port\"",
          AIArgs("[SOCKADDR_TEXT]", orig_sockaddr_text));
    }
    else if (AI_UNLIKELY(sockaddr_text[len] != ':'))
    {
      THROW_ALERTC(SocketAddress_decode_sockaddr_parse_error,
          "\"[SOCKADDR_TEXT]\": IPv4 extra characters",
          AIArgs("[SOCKADDR_TEXT]", orig_sockaddr_text)("[REST]", sockaddr_text));
    }
    sockaddr_text.remove_prefix(len + 1);
    try
    {
      len = decode_port(sockaddr_text, in_port);
    }
    catch (AIAlert::Error const& error)
    {
      THROW_ALERTC(SocketAddress_decode_sockaddr_parse_error,
          "\"[SOCKADDR_TEXT]\": ",
          AIArgs("[SOCKADDR_TEXT]", orig_sockaddr_text),
          error);
    }
  }
  else
    in_port = ntohs(port_h);
  if (AI_UNLIKELY(len != sockaddr_text.size()))
  {
    // Don't supply trailing characters.
    if (port_h == -1)
      THROW_ALERTC(SocketAddress_decode_sockaddr_parse_error,
          "\"[SOCKADDR_TEXT]\": trailing characters after port number",
          AIArgs("[SOCKADDR_TEXT]", orig_sockaddr_text));
    else
      THROW_ALERTC(SocketAddress_decode_sockaddr_parse_error,
          "\"[SOCKADDR_TEXT]\": trailing characters after address",
          AIArgs("[SOCKADDR_TEXT]", orig_sockaddr_text));
  }

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
    case AF_UNSPEC:
      // AF_UNSPEC should mean 'uninitialized', see the default constructor of SocketAddress.
      std::memcpy(&m_sockaddr, ptr, sizeof(struct sockaddr));
      break;
    default:
      Dout(dc::warning, "SocketAddress::move(SocketAddress&& other): sa_family is not AF_INET, AF_INET6, AF_UNIX or AF_UNSPEC.");
      std::memcpy(&m_sockaddr, ptr, sizeof(struct sockaddr));
      break;
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
    case AF_UNSPEC:
      // AF_UNSPEC should mean 'uninitialized', see the default constructor of SocketAddress.
      // And it is a bit suspicious when someone is trying to make a copy of something uninitialized.
      Dout(dc::warning, "Initializing a SocketAddress with an 'uninitialized' (default constructed) SocketAddress!");
      std::memcpy(&m_sockaddr, sa_addr, sizeof(struct sockaddr));
      break;
    default:
      Dout(dc::warning, "SocketAddress::init(struct sockaddr const*): sa_family is not AF_INET, AF_INET6 or AF_UNIX or AF_UNSPEC.");
      std::memcpy(&m_sockaddr, sa_addr, sizeof(struct sockaddr));
      break;
  }
}

void SocketAddress::init(struct sockaddr const* sa_addr, uint16_t port)
{
  switch (sa_addr->sa_family)
  {
    case AF_INET:
      std::memcpy(&m_sockaddr, sa_addr, sizeof(struct sockaddr_in));
      reinterpret_cast<struct sockaddr_in*>(&m_sockaddr)->sin_port = htons(port);
      break;
    case AF_INET6:
      std::memcpy(&m_sockaddr, sa_addr, sizeof(struct sockaddr_in6));
      reinterpret_cast<struct sockaddr_in6*>(&m_sockaddr)->sin6_port = htons(port);
      break;
    default:
      DoutFatal(dc::core, "SocketAddress::init(struct sockaddr const*, uint16_t): sa_family is not AF_INET or AF_INET6.");
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
      case AF_UNSPEC:
        res = 0;
        break;
      default:
        return false;
    }
  }
  return res == val;
}

//============================================================================
// Error code handling.
// See https://akrzemi1.wordpress.com/2017/07/12/your-own-error-code/

//----------------------------------------------------------------------------
// evio error category

namespace {

struct ErrorCategory : std::error_category
{
  char const* name() const noexcept override;
  std::string message(int ev) const override;
};

char const* ErrorCategory::name() const noexcept
{
  return "evio";
}

std::string ErrorCategory::message(int ev) const
{
  switch (static_cast<error_codes>(ev))
  {
    case SocketAddress_decode_sockaddr_parse_error:
      return "evio::SocketAddress::decode_sockaddr parse error";
    case SocketAddress_make_sockaddr_un_path_too_long:
      return "UNIX socket path is too long";
    default:
      return "evio::SocketAddress::decode_sockaddr (unrecognized error)";
  }
}

ErrorCategory const theErrorCategory { };

} // namespace

std::error_code make_error_code(error_codes code)
{
  return std::error_code(static_cast<int>(code), theErrorCategory);
}

//----------------------------------------------------------------------------
// gai error codes (as returned by getnameinfo(3), getaddrinfo(3), etc)

namespace {

struct GaiErrorCategory : std::error_category
{
  char const* name() const noexcept override;
  std::string message(int ev) const override;
};

char const* GaiErrorCategory::name() const noexcept
{
  return "gai";
}

std::string GaiErrorCategory::message(int ev) const
{
  return gai_strerror(ev);
}

GaiErrorCategory const theGaiErrorCategory { };

} // namespace

std::error_code make_error_code(gai_error_codes code)
{
  return std::error_code(static_cast<int>(code), theGaiErrorCategory);
}

} // namespace evio
