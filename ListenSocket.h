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

#include "Device.h"
#include "debug.h"
#include "inet_support.h"
#include <sys/un.h>
#include <sys/socket.h>

namespace evio {

//=============================================================================
//
// class ListenSocketDevice
//
// Base class for listen sockets, spawning connected socket streams.
//
// SYNOPSIS
//
// This class implements listen() for "server" sockets.
//

class ListenSocketDevice : public InputDevice
{
 private:
  //---------------------------------------------------------------------------
  // Private attribute:
  //

  // The address we bind to.
  struct sockaddr* m_bind_addr;

  //---------------------------------------------------------------------------
  // Private manipulator:
  //

  // Set the bind address to its new value.
  // If this is a UNIX domain socket then at destruction of this object,
  // the bind address will be unlink(2)-ed.
  void set_bind_addr(struct sockaddr* bind_addr)
  {
    if (m_bind_addr)
    {
      if (m_bind_addr->sa_family == AF_UNIX)
        unlink(((struct sockaddr_un*)m_bind_addr)->sun_path);
      free(m_bind_addr);
    }
    m_bind_addr = bind_addr;
  }

 public:
  //---------------------------------------------------------------------------
  // Constructors:
  //

  // Make an ListenSocketDevice for association with a new TCP/IP socket.
  // If you use this constructor, you need to call `listen' before it will actually do anything.
  ListenSocketDevice(Dev2Buf* ibuf) : InputDevice(ibuf), m_bind_addr(nullptr)
  {
    DoutEntering(dc::evio, "ListenSocketDevice() [" << this << ']');
  }

  // Make a ListenSocket associated with a new TCP/IP listen socket and start listening on port `port'.
  //
  // Connecting clients will spawn an object of `SOCK_TYPE' which must be a Socket<>.
  // This new object then will generate the events (virtual function) `new_message_received' etcetera when they occur.
  // `backlog' is the size of the client queue waiting for accept().
  ListenSocketDevice(Dev2Buf* ibuf, unsigned short int port, int backlog = 4) : InputDevice(ibuf), m_bind_addr(nullptr)
  {
    DoutEntering(dc::evio, "ListenSocket(" << port << ", " << backlog << ") [" << this << ']');
    listen(port, backlog);
  }

 // Make a ListenSocket associated with a new unix domain listen socket and start listening on `path'.
 // `backlog' is the size of the client queue waiting for accept().
  ListenSocketDevice(Dev2Buf* ibuf, char const* path, int backlog = 4) : InputDevice(ibuf), m_bind_addr(nullptr)
  {
    DoutEntering(dc::evio, "ListenSocket(\"" << path << "\", " << backlog << ')');
    listen(path, backlog);
  }

  // Make a `ListenSocket' from a listen socket filedescriptor `fd'.
  // `bind_addr' must be an address allocated with new, being the address this listen socket is bound to.
  ListenSocketDevice(Dev2Buf* ibuf, int fd, struct sockaddr* bind_addr) : InputDevice(ibuf), m_bind_addr(bind_addr)
  {
    DoutEntering(dc::evio, "ListenSocket(" << fd << ", {" << *bind_addr << "}) [" << this << ']');
    init(fd);
    start();
  }

public:
  //---------------------------------------------------------------------------
  // Public methods:
  //

  // Open a socket for listening on port `port' explicitly, after the
  // associated 'ListenSocketDevice' object already exists (for
  // instance, after using the default constructor).
  // `backlog' is the size of the client queue waiting for accept().
  void listen(unsigned short int port, int backlog);

  // Open a socket in de UNIX domain for listening on `path' explicitly,
  // after the associated 'ListenSocketDevice' object already exists (for
  // instance, after using the default constructor).
  // `backlog' is the size of the client queue waiting for accept().
  void listen(char const* path, int backlog);

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

private:
  //---------------------------------------------------------------------------
  // Private methods:
  //

  // Do the actual listen stuff.
  bool priv_listen(struct sockaddr* bind_addr, int backlog);

 protected:
  ~ListenSocketDevice()
  {
    if (m_bind_addr)
    {
      if (m_bind_addr->sa_family == AF_UNIX)
      {
        char* tmp = ((struct sockaddr_un*)m_bind_addr)->sun_path;
        if (*tmp)       // Can be made 0 in the debug daemon
          unlink(tmp);
      }
      free(m_bind_addr);
    }
  }
};

template<typename SOCK_TYPE>
class ListenSocket : public ListenSocketDevice
{
 public:
  using ListenSocketDevice::ListenSocketDevice;

 private:
  // Called from ListenSocketDevice::read_from_fd() to spawn the new socket.
  void spawn_accepted(int fd, struct sockaddr* addr) override;

 protected:
  // Called when a new connection is accepted.
  virtual void new_connection(SOCK_TYPE& UNUSED_ARG(connection)) { }
};

template<typename SOCK_TYPE>
void ListenSocket<SOCK_TYPE>::spawn_accepted(int fd, struct sockaddr* addr)
{
  SOCK_TYPE* sock = new SOCK_TYPE;
  AllocTag1(sock);
  sock->init(fd, addr);
  new_connection(*sock);
}

} // namespace evio
