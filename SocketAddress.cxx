#include "sys.h"
#include "debug.h"
#include "SocketAddress.h"
#include "utils/macros.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <iostream>
#include <charconv>

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
    ASSERT(sv.size() > 2 && sv[1] == ':');      // An IPv6 address can only start with a colon if that is a double colon.
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
    addr[i] = hextet >> 8;
    addr[i + 1] = hextet & 0xff;
    i += 2;
    if (i == 16 || result.ptr == end || *result.ptr == ']')
    {
      p = result.ptr;
      break;
    }
    if (*result.ptr == '.')
    {
      i -= 2;
      if (saw_colon)    // IPv6?
      {
        ASSERT(saw_double_colon == 0 && i == 2 && addr[0] == 0xff && addr[1] == 0xff);    // IPv4 mapping only allowed after ::ffff:
        sv.remove_prefix(5);      // Skip over the 'ffff:'.
        len += 5;
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

// Possible formats:
//
// ddd.ddd.ddd.ddd:ppppp (optional brackets around ddd.ddd.ddd.ddd, but not recommended).
// [hhhh:hhhh:hhhh:hhhh:hhhh:hhhh:hhhh:hhhh]:ppppp
// [::ffff:ddd.ddd.ddd.ddd]:ppppp (the brackets are optional in this case).
SocketAddress::SocketAddress(std::string_view sockaddr_txt)
{
  bool has_brackets = sockaddr_txt.front() == '[';
  if (has_brackets)
    sockaddr_txt.remove_prefix(1);
  uint8_t addr[16];
  size_t len = decode_ip_address(sockaddr_txt, m_sockaddr.sa_family, addr);
  if (has_brackets)
  {
    ASSERT(len < sockaddr_txt.size() && sockaddr_txt[len] == ']');
    ++len;
  }
  ASSERT(len < sockaddr_txt.size() && sockaddr_txt[len] == ':');
  sockaddr_txt.remove_prefix(len + 1);

  in_port_t in_port;
  len = decode_port(sockaddr_txt, in_port);
  ASSERT(len == sockaddr_txt.size());

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

} // namespace evio
