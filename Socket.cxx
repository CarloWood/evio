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

bool Socket::connect(SocketAddress remote_address, size_t rcvbuf_size, size_t sndbuf_size, SocketAddress if_addr)
{
  if (is_open())
    return false;

  // The address to connect needs to make sense.
  ASSERT(!remote_address.is_unspecified());

  Dout(dc::system|continued_cf, "socket(" << remote_address.family() << ", SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0) = ");
  int fd = socket(remote_address.family(), SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  Dout(dc::finish|cond_error_cf(fd < 0), fd);
  if (fd < 0)
    return false;

  if (!if_addr.is_unspecified())
  {
    if (bind(fd, if_addr, size_of_addr(if_addr)) == -1)
      DoutFatal(dc::fatal|error_cf, "bind: " << if_addr);
  }

  Dout(dc::system|continued_cf, "connect(" << fd << ", " << remote_address << ", " << size_of_addr(remote_address) << ") = ");
  int ret = ::connect(fd, remote_address, size_of_addr(remote_address));
  if (ret < 0 && errno != EINPROGRESS)
  {
    Dout(dc::finish|error_cf, ret);
    Dout(dc::system|continued_cf, "close(" << fd << ") = ");
    DEBUG_ONLY(ret =) ::close(fd);
    Dout(dc::finish|cond_error_cf(ret < 0), ret);
    return false;
  }
  Dout(dc::finish|cond_error_cf(ret < 0), ret);

  init(fd, remote_address, rcvbuf_size, sndbuf_size, true);

  return true;
}

void Socket::init(int fd, SocketAddress const& remote_address, size_t rcvbuf_size, size_t sndbuf_size, bool signal_connected)
{
#ifdef CWDEBUG
  if (is_open())
    DoutFatal(dc::core, "Trying to `init' a Socket that is already open.");
#endif

  if (!m_remote_address.is_unspecified())
    Dout(dc::warning, "Socket::init: Already connected to " << m_remote_address << " ?!");

  // Call Socket::input and/or Socket::output before calling Socket::init.
  // If you don't call either - then this socket is not usable for input/output respectively!
  ASSERT(m_ibuffer || m_obuffer);

  m_remote_address = remote_address;

  m_rcvbuf_size = rcvbuf_size;
  m_sndbuf_size = sndbuf_size;
  m_signal_connected = signal_connected;

  if (remote_address.is_ip())
  {
    try
    {
      if (m_ibuffer)
        set_rcvsockbuf(fd, rcvbuf_size, m_ibuffer->minimum_block_size());
      if (m_obuffer)
        set_sndsockbuf(fd, sndbuf_size, m_obuffer->minimum_block_size());
    }
    catch (AIAlert::Error const& error)
    {
      Dout(dc::system|continued_cf, "close(" << fd << ") = ");
      DEBUG_ONLY(int ret =) ::close(fd);
      Dout(dc::finish|cond_error_cf(ret == -1), ret);
      THROW_ALERT("Socket::init([FD], [SOCKET_ADDRESS], [RCVBUF_SIZE], [SNDBUF_SIZE]):",
          AIArgs("[FD]", fd)("[SOCKET_ADDRESS]", remote_address)("[RCVBUF_SIZE]", rcvbuf_size)("[SNDBUF_SIZE]", sndbuf_size),
          error);
    }
  }

  FileDescriptor::init(fd);     // link in
  if (m_ibuffer)
    start_input_device();
  if (m_signal_connected || (m_obuffer && !m_obuffer->buffer_empty()))
    start_output_device();
}

void Socket::write_to_fd(int fd)
{
  if (AI_UNLIKELY(m_signal_connected))
  {
    m_signal_connected = false;
    connected();
    if (!m_obuffer || m_obuffer->buffer_empty())
    {
      stop_output_device();
      return;
    }
  }
  OutputDevice::write_to_fd(fd);
}

void Socket::connected()
{
  DoutEntering(dc::evio, "Socket::connected()");
  // Derive from Socket to implement this.
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
