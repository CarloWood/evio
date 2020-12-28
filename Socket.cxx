/**
 * evio -- A cwm4 git submodule for adding support for buffered, iostream oriented, epoll based I/O.
 *
 * @file
 * @brief Definition of class Socket.
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
#include "Socket.h"
#include "EventLoopThread.h"
#include "utils/AIAlert.h"
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <cstring>
#include <cerrno>

namespace evio {

//static
void Socket::set_sock_buffers(int fd, size_t input_minimum_block_size, size_t output_minimum_block_size, size_t rcvbuf_size, size_t sndbuf_size)
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

bool Socket::connect(SocketAddress const& remote_address, size_t rcvbuf_size, size_t sndbuf_size, SocketAddress const& if_addr)
{
  DoutEntering(dc::evio, "Socket::connect(" << remote_address << ", " << rcvbuf_size << ", " << sndbuf_size << ", " << if_addr << ") [" << this << "]");

  if (state_t::rat(m_state)->m_flags.is_open())
    return false;

  // The address to connect needs to make sense.
  ASSERT(!remote_address.is_unspecified());

  Dout(dc::system|continued_cf, "socket(" << remote_address.family() << ", SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0) = ");
  int fd = socket(remote_address.family(), SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  Dout(dc::finish|cond_error_cf(fd < 0), fd);
  if (fd < 0)
    return false;

  // Send and receive buffer sizes must be set before calling connect().
  if (remote_address.is_ip())
  {
    // If m_ibuffer/m_obuffer is nullptr then the socket isn't going to be used in that direction,
    // so set a "random" value, but non-zero because that causes an assert.
    set_sock_buffers(fd, m_ibuffer ? m_ibuffer->m_minimum_block_size : 1, m_obuffer ? m_obuffer->m_minimum_block_size : 1, rcvbuf_size, sndbuf_size);
  }

  if (!if_addr.is_unspecified())
  {
    if (bind(fd, if_addr, size_of_addr(if_addr)) == -1)
    {
      Dout(dc::warning|error_cf, "bind: " << if_addr);
      return false;
    }
  }

  Dout(dc::system|continued_cf, "connect(" << fd << ", " << remote_address << ", " << size_of_addr(remote_address) << ") = ");
  int ret = ::connect(fd, remote_address, size_of_addr(remote_address));
  if (ret < 0 && errno != EINPROGRESS)
  {
    Dout(dc::finish|error_cf, ret);
    Dout(dc::system|continued_cf, "close(" << fd << ") = ");
    CWDEBUG_ONLY(ret =) ::close(fd);
    Dout(dc::finish|cond_error_cf(ret < 0), ret);
    return false;
  }
  Dout(dc::finish|cond_error_cf(ret < 0), ret);

  // Either call set_protocol_decoder to give the socket an input buffer, or
  // call set_source AND fill the buffer with something (including a std::flush), or
  // call on_connected on the socket, before calling connect().
  // Otherwise the socket is not monitored (nothing to read or write) and will just sit there.
  ASSERT(m_ibuffer || (m_obuffer && m_obuffer->StreamBufConsumer::nothing_to_get().is_false()) || m_connected);

  init(fd, remote_address);

  return true;
}

void Socket::init(int fd, SocketAddress const& remote_address)
{
#ifdef CWDEBUG
  if (get_flags().is_open())
    DoutFatal(dc::core, "Trying to `init' a Socket that is already open.");
#endif

  if (!m_remote_address.is_unspecified())
    Dout(dc::warning, "Socket::init: Already connected to " << m_remote_address << " ?!");

  // Call Socket::set_source and/or Socket::set_protocol_decoder before calling Socket::init.
  // If you don't call either - then this socket is not usable for input/output respectively!
  ASSERT(m_ibuffer || m_obuffer);

  m_remote_address = remote_address;
  m_connected_flags = 0;

  fd_init(fd);     // link in
  state_t::wat state_w(m_state);
  if (m_ibuffer)
    start_input_device(state_w);
  else
    Dout(dc::warning, "This socket does not have an input buffer; input device not started.");
  if (m_connected)
    start_output_device(state_w);
  else if (m_obuffer)
  {
    if (m_obuffer->StreamBufConsumer::nothing_to_get().is_false())      // We are both consumer and producer.
      start_output_device(state_w);
  }
  else
  {
    ASSERT(m_ibuffer);
    Dout(dc::warning, "This socket does not have an output buffer; output device not started.");
  }
}

void Socket::read_from_fd(int& allow_deletion_count, int fd)
{
  // This is false when m_connected is set, because in that case we monitor
  // this socket for writablity and use that to detect when it is connected.
  // Otherwise it is only true at most once.
  if (AI_UNLIKELY(!(m_connected_flags & is_connected)) && !m_connected)
    m_connected_flags |= is_connected;
  // Call base class implementation.
  InputDevice::read_from_fd(allow_deletion_count, fd);
}

// Read thread.
void Socket::write_to_fd(int& allow_deletion_count, int fd)
{
  if (AI_UNLIKELY(!(m_connected_flags & is_connected)))
  {
    // As soon as we can write to a file descriptor, we are connected.
    m_connected_flags |= is_connected;
    if (m_connected)
    {
      m_connected(allow_deletion_count, true); // Signal successful connect.
      // Now there is no longer a need to monitor the fd for writablity if the output buffer is empty.
      if (m_obuffer)
      {
        utils::FuzzyCondition condition_nothing_to_get([m_obuffer = m_obuffer]{
            return m_obuffer->StreamBufConsumer::nothing_to_get();
        });
        if (condition_nothing_to_get.is_momentary_true() &&
            stop_output_device(allow_deletion_count, condition_nothing_to_get))
          return;
      }
      else
      {
        Dout(dc::warning, "Socket::write_to_fd: Closing output device because it has no output buffer [" << this << "]");
        stop_output_device(allow_deletion_count);
        return;
      }
    }
  }
  // Call base class implementation.
  OutputDevice::write_to_fd(allow_deletion_count, fd);
}

void Socket::read_returned_zero(int& allow_deletion_count)
{
  DoutEntering(dc::evio, "Socket::read_returned_zero({" << allow_deletion_count << "}) [" << this << "]");
  close(allow_deletion_count);
  if ((m_connected_flags & (is_connected|is_disconnected)) == is_connected)
  {
    m_connected_flags |= is_disconnected;
    if (m_disconnected)
      m_disconnected(allow_deletion_count, true); // Clean termination.
  }
  else if (m_connected)
    m_connected(allow_deletion_count, false); // Signal connect failure.
}

void Socket::read_error(int& allow_deletion_count, int CWDEBUG_ONLY(err))
{
  DoutEntering(dc::evio, "Socket::read_error({" << allow_deletion_count << "}, " << err << ") [" << this << "]");
  close(allow_deletion_count);
  if ((m_connected_flags & (is_connected|is_disconnected)) == is_connected)
  {
    m_connected_flags |= is_disconnected;
    if (m_disconnected)
      m_disconnected(allow_deletion_count, false); // Unclean termination.
  }
  else if (m_connected)
    m_connected(allow_deletion_count, false); // Signal connect failure.
}

SocketAddress Socket::local_address() const
{
  // Don't call this function when !is_open() (aka, init() was called).
  ASSERT(state_t::crat(m_state)->m_flags.is_open());
  SocketAddress result;
  socklen_t namelen = sizeof(result);

  if (getsockname(m_fd, result, &namelen) < 0)
  {
    std::ostringstream descr;
    descr << "getsockname(" << m_fd << ", " << std::hex << &result << ", [" << std::dec << namelen << "])";
    // This makes a copy of the string to AIAlert::Line::mXmlDesc before throwing.
    THROW_FALERTE(descr.str());
  }

  return result;
}

Socket::~Socket()
{
}

} // namespace evio
