/**
 * evio -- A cwm4 git submodule for adding support for buffered, iostream oriented, epoll based I/O.
 *
 * @file
 * @brief Declaration of class Socket.
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
  // Overridden to detect successful connections.
  void read_from_fd(int& allow_deletion_count, int fd) override;
  // Overridden to detect connection termination.
  void read_returned_zero(int& allow_deletion_count) override;
  // Overridden to detect connect failures and connection abortions.
  void read_error(int& allow_deletion_count, int err) override;
  // Overridden to detect connects.
  void write_to_fd(int& allow_deletion_count, int fd) override;

 protected:
  //---------------------------------------------------------------------------
  // Protected attributes
  //

  // The address of the remote socket; either what we connected to or the peer address of an accepted connection.
  SocketAddress m_remote_address;

  // Called, if onConnected() was called, as soon as the socket becomes writable for the first time
  // (in the case of TLSSocket when the TLS handshake completed) or when such permanently failed.
  std::function<void(int&, bool)> m_connected;
  // Called when a connection is terminated and onDisconnected() was called.
  std::function<void(int&, bool)> m_disconnected;

  uint8_t m_connected_flags;
  static constexpr uint8_t is_connected = 1;
  static constexpr uint8_t is_disconnected = 2;

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

  char const* get_path() const
  {
    // Don't call get_path for a non AF_UNIX socket.
    assert(m_remote_address.is_un());
    return reinterpret_cast<struct sockaddr_un const*>(static_cast<struct sockaddr const*>(m_remote_address))->sun_path;
  }

 public:
  //---------------------------------------------------------------------------
  // Constructor
  //

  Socket() { DoutEntering(dc::evio, "Socket::Socket() [" << this << "]"); }
  ~Socket();

  // Set the socket buffer sizes.
  static void set_sock_buffers(int fd, size_t input_minimum_block_size, size_t output_minimum_block_size, size_t rcvbuf_size = 0, size_t sndbuf_size = 0);

  // Call this to set a call back for the connected event.
  // The first argument is `allow_deletion_count` (should be passed to functions that need it, if any are called).
  // The second argument is `success` and signals whether or not the connect was successful or failed.
  void onConnected(std::function<void(int&, bool)>&& connected_cb)
  {
    // Call onConnected before calling init / connect.
    ASSERT(!get_flags().is_open());
    m_connected = std::move(connected_cb);
  }

  // Call this to set a call back for the disconnected event.
  // Success means it was a clean termination. Not called when the connect failed.
  void onDisconnected(std::function<void(int&, bool)>&& disconnected_cb)
  {
    // Call onDisconnected before calling init / connect.
    ASSERT(!get_flags().is_open());
    m_disconnected = std::move(disconnected_cb);
  }

  // Only useful for derived classes (ie, TLSSocket).
  virtual void set_sni(std::string const& UNUSED_ARG(ServerNameIndication)) { }

  // Associate this object with an existing and open socket `fd'.
  void init(int fd, SocketAddress const& socket_address);

  // Create a socket(2), bind it to if_addr, and call init().
  bool connect(SocketAddress const& socket_address, size_t rcvbuf_size = 0, size_t sndbuf_size = 0, SocketAddress const& if_addr = {});
};

} // namespace evio
