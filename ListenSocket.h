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
    ASSERT(!bind_addr.is_unspecified() && (m_bind_addr.is_unspecified() || state_t::rat(m_state)->m_flags.is_dead()));
    m_bind_addr = std::move(bind_addr);
    init(fd);
    state_t::wat state_w(m_state);
    start_input_device(state_w);
  }

  //---------------------------------------------------------------------------
  // Accessor:
  //

  struct sockaddr const* get_bind_addr() const { return m_bind_addr; }

 public:
  struct VT_type : InputDevice::VT_type
  {
    bool (*_maybe_out_of_fds)(ListenSocketDevice* self);
    // Called by read_from_fd() to actually spawn a SOCK_TYPE for the accepted fd.
    void (*_spawn_accepted)(ListenSocketDevice* self, int fd, SocketAddress const& remote_address);        // Pure virtual.
  };

  struct VT_impl : InputDevice::VT_impl
  {
    // Called when the listen socket is ready to accept a new client.
    //
    // The default `ListenSocket::read_from_fd' accepts a new client and spawns a new `SOCK_TYPE' accociated with the new client.
    static NAD_DECL(read_from_fd, InputDevice* self, int fd);                   // override

    // This method is called when we are possibly out of filedescriptors.
    // It should return `true' when this is true, and can optionally take
    // some action by overriding this function.
    //
    // The default `listen_sockstream_dct::maybe_out_of_fds' returns
    // true when `socket()' fails.
    static bool maybe_out_of_fds(ListenSocketDevice* self);			// New virtual function.

    // Virtual table of ListenSocketDevice.
    static constexpr VT_type VT{
      /*ListenSocketDevice*/
        /*InputDevice*/
      { nullptr,
        read_from_fd,
        hup,
        exceptional,
        read_returned_zero,
        read_error,
        data_received },
      maybe_out_of_fds,
      nullptr   // _spawn_accepted
    };
  };

  // Make a deep copy of VT_ptr.
  VT_type* clone_VT() override { return VT_ptr.clone(this); }
  utils::VTPtr<ListenSocketDevice, InputDevice> VT_ptr;

protected:
  //---------------------------------------------------------------------------
  // Protected events:
  //

  bool maybe_out_of_fds() { return VT_ptr->_maybe_out_of_fds(this); }
  void spawn_accepted(int fd, SocketAddress const& remote_address) { VT_ptr->_spawn_accepted(this, fd, remote_address); }

 public:
  //---------------------------------------------------------------------------
  // Constructors:
  //

  // Make a ListenSocketDevice for association with a new TCP/IP socket.
  // You need to call `listen' before it will actually do anything.
  ListenSocketDevice() : VT_ptr(this) { DoutEntering(dc::evio, "ListenSocketDevice() [" << this << ']'); }
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
  struct VT_type : ListenSocketDevice::VT_type
  {
    void (*_new_connection)(ListenSocket* self, accepted_socket_type& accepted_socket);
  };

  struct VT_impl : ListenSocketDevice::VT_impl
  {
    // Called from ListenSocketDevice::read_from_fd() to spawn the new socket.
    static void spawn_accepted(ListenSocketDevice* self, int fd, SocketAddress const& remote_address);

    // Called when a new connection is accepted.
    static void new_connection(ListenSocket* UNUSED_ARG(self), accepted_socket_type& UNUSED_ARG(accepted_socket)) { }

    // Virtual table of ListenSocket.
    static constexpr VT_type VT{
      /*ListenSocket*/
        /*ListenSocketDevice*/
      {   /*InputDevice*/
        { nullptr,
          read_from_fd,
          hup,
          exceptional,
          read_returned_zero,
          read_error,
          data_received },
        maybe_out_of_fds,
        spawn_accepted },       // Overridden
      new_connection
    };
  };

  VT_type* clone_VT() override { return VT_ptr.clone(this); }   // Make a deep copy of VT_ptr.
  utils::VTPtr<ListenSocket, ListenSocketDevice> VT_ptr;

 protected:
  void new_connection(accepted_socket_type& accepted_socket) { VT_ptr->_new_connection(this, accepted_socket); }

 public:
  ListenSocket() : VT_ptr(this) { }
};

template<typename ACCEPTED_SOCKET>
void ListenSocket<ACCEPTED_SOCKET>::VT_impl::spawn_accepted(ListenSocketDevice* _self, int fd, SocketAddress const& remote_address)
{
  ListenSocket<ACCEPTED_SOCKET>* self = static_cast<ListenSocket<ACCEPTED_SOCKET>*>(_self);
  auto sock = create<ACCEPTED_SOCKET>();
  sock->init(fd, remote_address);
  self->new_connection(*sock);
}

} // namespace evio
