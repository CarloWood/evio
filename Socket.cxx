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

bool Socket::connect(SocketAddress const& remote_address, size_t rcvbuf_size, size_t sndbuf_size, SocketAddress if_addr)
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
  m_connected_flags = signal_connected;

  if (remote_address.is_ip())
  {
    try
    {
      if (m_ibuffer)
        set_rcvsockbuf(fd, rcvbuf_size, m_ibuffer->m_minimum_block_size);
      if (m_obuffer)
        set_sndsockbuf(fd, sndbuf_size, m_obuffer->m_minimum_block_size);
    }
    catch (AIAlert::Error const& error)
    {
      Dout(dc::system|continued_cf, "close(" << fd << ") = ");
      CWDEBUG_ONLY(int ret =) ::close(fd);
      Dout(dc::finish|cond_error_cf(ret == -1), ret);
      THROW_ALERT("Socket::init([FD], [SOCKET_ADDRESS], [RCVBUF_SIZE], [SNDBUF_SIZE]):",
          AIArgs("[FD]", fd)("[SOCKET_ADDRESS]", remote_address)("[RCVBUF_SIZE]", rcvbuf_size)("[SNDBUF_SIZE]", sndbuf_size),
          error);
    }
  }

  FileDescriptor::init(fd);     // link in
  SingleThread type;
  if (m_ibuffer)
    start_input_device(type);
  if (signal_connected)
    start_output_device(type);
  else if (m_obuffer)
  {
    StreamBuf::GetThreadLock::rat get_area_rat(m_obuffer->get_area_lock(type));
    if (!m_obuffer->buffer_empty(get_area_rat))   // Must be the same thread as the thread that created the buffer.
      start_output_device(type);
  }
}

void Socket::VT_impl::read_from_fd(InputDevice* _self, int fd)
{
  Socket* self = static_cast<Socket*>(_self);
  // This is false when signal_connected is set, because in that case we monitor
  // this socket for writablity and use that to detect when it is connected.
  // Otherwise it is only true at most once.
  if (AI_UNLIKELY(!(self->m_connected_flags & (signal_connected|is_connected))))
  {
    self->m_connected_flags |= is_connected;
  }
  // Call base class implementation.
  InputDevice::VT_impl::read_from_fd(_self, fd);
}

// Read thread.
void Socket::VT_impl::write_to_fd(OutputDevice* _self, int fd)
{
  GetThread type;
  Socket* self = static_cast<Socket*>(_self);
  if (AI_UNLIKELY(!(self->m_connected_flags & is_connected)))
  {
    // As soon as we can write to a file descriptor, we are connected.
    self->m_connected_flags |= is_connected;
    if ((self->m_connected_flags & signal_connected))
    {
      self->connected(true);    // Signal successful connect.
      // Now there is not longer a need to monitor the fd for writablity if the output buffer is empty.
      if (self->m_obuffer)
      {
        utils::FuzzyCondition condition_empty_buffer([m_obuffer = self->m_obuffer, type]{
            StreamBuf::GetThreadLock::rat get_area_rat(m_obuffer->get_area_lock(type));
            return m_obuffer->StreamBufConsumer::buffer_empty(get_area_rat);
        });
        if (condition_empty_buffer.is_momentary_true())
        {
          self->stop_output_device(type, condition_empty_buffer);
          return;
        }
      }
      else
      {
        self->stop_output_device();
        return;
      }
    }
  }
  // Call base class implementation.
  OutputDevice::VT_impl::write_to_fd(_self, fd);
}

void Socket::VT_impl::connected(Socket* CWDEBUG_ONLY(self), bool CWDEBUG_ONLY(success))
{
  DoutEntering(dc::evio, "Socket::connected(" << success << ") [" << self << "]");
  // Derive from Socket to implement this.
}

RefCountReleaser Socket::VT_impl::read_returned_zero(InputDevice* _self)
{
  Socket* self = static_cast<Socket*>(_self);
  DoutEntering(dc::evio, "Socket::read_returned_zero() [" << self << "]");
  self->m_connected_flags |= is_disconnected;
  RefCountReleaser need_allow_deletion = self->close();
  self->disconnected(true);     // Clean termination.
  return need_allow_deletion;
}

RefCountReleaser Socket::VT_impl::read_error(InputDevice* _self, int CWDEBUG_ONLY(err))
{
  Socket* self = static_cast<Socket*>(_self);
  DoutEntering(dc::evio, "Socket::read_error(" << err << ") [" << self << "]");
  RefCountReleaser need_allow_deletion = self->close();
  if ((self->m_connected_flags & (signal_connected|is_connected)) == signal_connected)
    self->connected(false);     // Signal connect failure.
  if ((self->m_connected_flags & is_connected))
  {
    self->m_connected_flags |= is_disconnected;
    self->disconnected(false);  // Unclean termination.
  }
  return need_allow_deletion;
}

void Socket::VT_impl::disconnected(Socket* CWDEBUG_ONLY(self), bool CWDEBUG_ONLY(success))
{
  DoutEntering(dc::evio, "Socket::connected(" << success << ") [" << self << "]");
  // Clone VT and override to implement this.
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

Socket::~Socket() noexcept
{
}

} // namespace evio
