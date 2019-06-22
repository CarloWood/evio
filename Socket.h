// evio -- Event Driven I/O support.
//
//! @file
//! @brief Declaration of class Socket.
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

#include "SocketAddress.h"
#include "InputDevice.h"
#include "OutputDevice.h"
#include "inet_support.h"
#include "debug.h"
#include <netinet/in.h>
#include <sys/un.h>

namespace evio {

class Socket;

//=============================================================================
//
// class Socket
//
// SYNOPSIS
//
// This class implements connect() for "client" sockets.
//

class Socket : public InputDevice, public OutputDevice
{
 public:
  struct VT_type : InputDevice::VT_type, OutputDevice::VT_type
  {
    NAD_DECL((*_connected), Socket*, bool);
    NAD_DECL((*_disconnected), Socket*, bool success);
  };

  struct VT_impl : InputDevice::VT_impl, OutputDevice::VT_impl
  {
    // Overridden to detect successful connections.
    static NAD_DECL(read_from_fd, InputDevice* _self, int fd);
    // Overridden to detect connection termination.
    static NAD_DECL(read_returned_zero, InputDevice* _self);
    // Overridden to detect connect failures and connection abortions.
    static NAD_DECL(read_error, InputDevice* _self, int err);
    // Overridden to detect connects.
    static NAD_DECL(write_to_fd, OutputDevice* _self, int fd);
    // Called, if signal_connected == true was passed to init(), as soon as the socket becomes writable for the first time.
    static NAD_DECL(connected, Socket* self, bool success);
    // Called when a connection is terminated. Success means it was a clean termination. Not called when the connect failed.
    static NAD_DECL(disconnected, Socket* self, bool success);

    static constexpr VT_type VT{
      /*Socket*/
        /*InputDevice*/
      { nullptr,
        read_from_fd,
        hup,
        exceptional,
        read_returned_zero,
        read_error,
        data_received },
        /*OutputDevice*/
      { nullptr,
        write_to_fd,
        write_error },
      connected,
      disconnected
    };
  };

  // Make a deep copy of VT_ptr.
  VT_type* clone_VT() override { return VT_ptr.clone(this); }

  utils::VTPtr<Socket, InputDevice, OutputDevice> VT_ptr;

 protected:
  //---------------------------------------------------------------------------
  // Protected attributes
  //

  // The address of the remote socket; either what we connected to or the peer address of an accepted connection.
  SocketAddress m_remote_address;

  // The receive socket buffer that we want to be set.
  // The actual size can be set to a larger value, see net/inet_support.cc
  // A value of 0 here means: use a size that depends on the minimum block
  // size of our input buffer.
  size_t m_rcvbuf_size;

  // Idem for the send socket buffer (except, output buffer).
  size_t m_sndbuf_size;

  int m_connected_flags;
  static constexpr int signal_connected = 1;    // When set, call connected() as soon as fd is writable.
  static constexpr int is_connected = 2;
  static constexpr int is_disconnected = 4;

 public:
  //---------------------------------------------------------------------------
  // Public accessors:
  //

  // Returns the remote IP number and port that this socket connected with.
  // Only valid when `is_open' returns true.
  SocketAddress address() const { return m_remote_address; }

  // Returns the local IP number and port of this socket (the bind address).
  // Only valid when `is_open' returns true.
  SocketAddress local_address() const;

  // Accessor for m_rcvbuf_size.
  size_t get_rcvbuf_size() const { return m_rcvbuf_size; }

  // Accessor for m_sndbuf_size.
  size_t get_sndbuf_size() const { return m_sndbuf_size; }

  char const* get_path() const
  {
    // Don't call get_path for a non AF_UNIX socket.
    assert(m_remote_address.is_un());
    return reinterpret_cast<struct sockaddr_un const*>(static_cast<struct sockaddr const*>(m_remote_address))->sun_path;
  }

 private:
  // Event, called from VT_impl::write_to_fd (success) and VT_impl::read_error (failure).
  NAD_DECL(connected, bool success) { NAD_CALL(VT_ptr->_connected, this, success); }
  // Event, called from VT_impl::read_returned_zero (success) and VT_impl::read_error (failure).
  NAD_DECL(disconnected, bool success) { NAD_CALL(VT_ptr->_disconnected, this, success); }

 public:
  //---------------------------------------------------------------------------
  // Constructor
  //

  Socket() : VT_ptr(this), m_rcvbuf_size(0), m_sndbuf_size(0) { DoutEntering(dc::evio, "Socket::Socket() [" << this << "]"); }
  ~Socket() noexcept;

  // Associate this object with an existing and open socket `fd'.
  void init(int fd, SocketAddress const& socket_address, size_t rcvbuf_size = 0, size_t sndbuf_size = 0, bool signal_connected = false);

  // Create a socket(2), bind it to if_addr, and call init().
  bool connect(SocketAddress const& socket_address, size_t rcvbuf_size = 0, size_t sndbuf_size = 0, SocketAddress if_addr = {});
};

} // namespace evio
