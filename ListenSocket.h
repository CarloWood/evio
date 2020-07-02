/**
 * evio -- A cwm4 git submodule for adding support for buffered, iostream oriented, epoll based I/O.
 *
 * @file
 * @brief Declaration of class ListenSocket.
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

#pragma once

#include "InputDevice.h"
#include "debug.h"
#include "inet_support.h"
#include "Socket.h"
#include <sys/un.h>
#include <sys/socket.h>

namespace evio {

//=============================================================================
//
// class ListenSocketDevice
//
// Base class for ListenSocket.
//

class ListenSocketDevice : public InputDevice
{
 public:
  // Called when the listen socket is ready to accept a new client.
  //
  // The default `ListenSocket::read_from_fd' accepts a new client and spawns a new `SOCK_TYPE' accociated with the new client.
  void read_from_fd(int& allow_deletion_count, int fd) override;

  // This method is called when we are possibly out of filedescriptors.
  // It should return `true' when this is true, and can optionally take
  // some action by overriding this function.
  //
  // The default `listen_sockstream_dct::maybe_out_of_fds' returns
  // true when `socket()' fails.
  virtual bool maybe_out_of_fds();

  virtual void spawn_accepted(int fd, SocketAddress const& remote_address) = 0;

 private:
  SocketAddress m_bind_addr;            // The address we bind to.

 private:
  virtual size_t input_minimum_block_size() const = 0;
  virtual size_t output_minimum_block_size() const = 0;

 public:
  //---------------------------------------------------------------------------
  // Public methods:
  //

  // After construction listen must be called.

  // Open the listen socket.
  // `sockaddr' is the interface to bind to plus the port to listen on; or a UNIX socket.
  // `backlog' is the size of the client queue waiting for accept().
  //
  // When a new connection is accepted the virtual function spawn_accepted will be called.
  //
  // Passing a value of zero to rcvbuf_size / sndbuf_size will cause the virtual function
  // input_minimum_block_size() / output_minimum_block_size() to be used respectively.
  void listen(SocketAddress&& sockaddr, int backlog = 4, size_t rcvbuf_size = 0, size_t sndbuf_size = 0);

  // Convenience function in case you want to pass an lvalue.
  void listen(SocketAddress const& sockaddr, int backlog = 4, size_t rcvbuf_size = 0, size_t sndbuf_size = 0)
  {
    listen(SocketAddress(sockaddr), backlog, rcvbuf_size, sndbuf_size);
  }

  // Start listening on an existing listen socket with filedescriptor fd.
  // bind_addr must be the address this listen socket is bound to.
  // Afterwards the file descriptor is owned (will be closed) by evio.
  void listen(int fd, SocketAddress&& bind_addr)
  {
    DoutEntering(dc::evio, "listen(" << fd << ", " << bind_addr << ") [" << this << ']');
    // The socket family of bind_addr must be specified.
    // The ListenSocket must be closed before you can reuse it.
    ASSERT(!bind_addr.is_unspecified() && (m_bind_addr.is_unspecified() || state_t::rat(m_state)->m_flags.is_dead()));
    m_bind_addr = std::move(bind_addr);
    fd_init(fd);
    state_t::wat state_w(m_state);
    start_input_device(state_w);
  }

  //---------------------------------------------------------------------------
  // Accessor:
  //

  struct sockaddr const* get_bind_addr() const { return m_bind_addr; }

 public:
  //---------------------------------------------------------------------------
  // Constructors:
  //

  // Make a ListenSocketDevice for association with a new TCP/IP socket.
  // You need to call `listen' before it will actually do anything.
  ListenSocketDevice() { DoutEntering(dc::evio, "ListenSocketDevice() [" << this << ']'); }
};

//=============================================================================
//
// Class ListenSocket
//
// This class implements listen() for "server" sockets.
//
template<typename ACCEPTED_SOCKET>
class ListenSocket : public ListenSocketDevice
{
 public:
  using accepted_socket_type = ACCEPTED_SOCKET;

 public:
  // Called from ListenSocketDevice::read_from_fd() to spawn the new socket.
  void spawn_accepted(int fd, SocketAddress const& remote_address) override;

  // Called when a new connection is accepted.
  virtual void new_connection(accepted_socket_type& UNUSED_ARG(accepted_socket)) { }

 public:
  ListenSocket() { }

 private:
  size_t input_minimum_block_size() const override;
  size_t output_minimum_block_size() const override;
};

template<typename ACCEPTED_SOCKET>
void ListenSocket<ACCEPTED_SOCKET>::spawn_accepted(int fd, SocketAddress const& remote_address)
{
  auto sock = create<ACCEPTED_SOCKET>();
  sock->init(fd, remote_address);
  new_connection(*sock);
}

template<typename ACCEPTED_SOCKET>
size_t ListenSocket<ACCEPTED_SOCKET>::input_minimum_block_size() const
{
  // Sorry, but for this ACCEPTED_SOCKET::input_protocol_type needs to have a default constructor.
  typename ACCEPTED_SOCKET::input_protocol_type input;
  return StreamBuf::round_up_minimum_block_size(input.minimum_block_size());
}

template<typename ACCEPTED_SOCKET>
size_t ListenSocket<ACCEPTED_SOCKET>::output_minimum_block_size() const
{
  // Sorry, but for this ACCEPTED_SOCKET::output_protocol_type needs to have a default constructor.
  typename ACCEPTED_SOCKET::output_protocol_type output;
  return StreamBuf::round_up_minimum_block_size(output.minimum_block_size());
}

} // namespace evio
