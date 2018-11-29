// evio -- Event Driven I/O support.
//
//! @file
//! @brief Declaration of class ListenSocket.
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
 private:
  SocketAddress m_bind_addr;            // The address we bind to.

 public:
  //---------------------------------------------------------------------------
  // Constructors:
  //

  // Make a ListenSocketDevice for association with a new TCP/IP socket.
  // You need to call `listen' before it will actually do anything.
  ListenSocketDevice()
  {
    DoutEntering(dc::evio, "ListenSocketDevice() [" << this << ']');
  }

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
  void listen(SocketAddress&& sockaddr, int backlog = 4);

  // Convenience function in case you want to pass an lvalue.
  void listen(SocketAddress const& sockaddr, int backlog = 4) { listen(SocketAddress(sockaddr), backlog); }

  // Start listening on an existing listen socket with filedescriptor fd.
  // bind_addr must be the address this listen socket is bound to.
  // Afterwards the file descriptor is owned (will be closed) by evio.
  void listen(int fd, SocketAddress&& bind_addr)
  {
    DoutEntering(dc::evio, "listen(" << fd << ", " << bind_addr << ") [" << this << ']');
    // The socket family of bind_addr must be specified.
    // The ListenSocket must be closed before you can reuse it.
    ASSERT(!bind_addr.is_unspecified() && (m_bind_addr.is_unspecified() || is_dead()));
    m_bind_addr = std::move(bind_addr);
    init(fd);
    start_input_device();
  }

  // Close the socket associated with this object.
  void close()
  {
    close_input_device();
  }

  //---------------------------------------------------------------------------
  // Accessor:
  //

  struct sockaddr const* get_bind_addr() const { return m_bind_addr; }

protected:
  //---------------------------------------------------------------------------
  // Protected events:
  //

  // Called when the listen socket is ready to accept a new client.
  //
  // The default `ListenSocket::read_from_fd' accepts a new client and spawns a new `SOCK_TYPE' accociated with the new client.
  void read_from_fd(int fd) override;

  // Called by read_from_fd() to actually spawn a SOCK_TYPE for the accepted fd.
  virtual void spawn_accepted(int fd, struct sockaddr* addr) = 0;

  // This method is called when we are possibly out of filedescriptors.
  // It should return `true' when this is true, and can optionally take
  // some action by overriding this function.
  //
  // The default `listen_sockstream_dct::maybe_out_of_fds' returns
  // true when `socket()' fails.
  virtual bool maybe_out_of_fds();
};

//=============================================================================
//
// Class ListenSocket
//
// This class implements listen() for "server" sockets.
//
template<typename DECODER, typename OUTPUT>
class ListenSocket : public ListenSocketDevice
{
 public:
  using ListenSocketDevice::ListenSocketDevice;

 private:
  // Called from ListenSocketDevice::read_from_fd() to spawn the new socket.
  void spawn_accepted(int fd, struct sockaddr* addr) override;

 protected:
  // Called when a new connection is accepted.
  virtual void new_connection(OUTPUT& UNUSED_ARG(connection)) { }
};

template<typename DECODER, typename OUTPUT>
struct SpawnedSocket : public Socket
{
  DECODER m_decoder;
  OUTPUT m_output;

  SpawnedSocket()
  {
    input(m_decoder);
    output(m_output);
  }
};

template<typename DECODER, typename OUTPUT>
void ListenSocket<DECODER, OUTPUT>::spawn_accepted(int fd, struct sockaddr* addr)
{
  auto sock = create<SpawnedSocket<DECODER, OUTPUT>>();
  sock->init(fd, addr);
  new_connection(sock->m_output);
}

} // namespace evio
