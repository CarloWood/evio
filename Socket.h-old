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

#include "Device.h"
#include "SocketAddress.h"
#include "inet_support.h"
#include "debug.h"
#include <netinet/in.h>
#include <sys/un.h>

namespace evio {

//=============================================================================
//
// class SocketDevice
//
// Base class for 'connect' sockets.
//
// SYNOPSIS
//
// This class implements connect() for "client" sockets.
//

class SocketDevice : public virtual IOBase
{
 protected:
  //---------------------------------------------------------------------------
  // Protected attributes
  //

  // The connect point, nullptr when not yet initialized.
  struct sockaddr* m_addr;

  // The local bind point, nullptr when not bound.
  struct sockaddr* m_local_addr;

  // The receive socket buffer that we want to be set.
  // The actual size can be set to a larger value, see net/inet_support.cc
  // A value of 0 here means: use the same size as the size of our buffer.
  size_t m_rcvbuf_size;

  // Idem for the send socket buffer.
  size_t m_sndbuf_size;

  //---------------------------------------------------------------------------
  // Constructor
  //

  SocketDevice() : m_addr(nullptr), m_local_addr(nullptr) { }

 private:
  //---------------------------------------------------------------------------
  // Private methods
  //

  // Generic socket(2)/connect(2) method.
  // Returns true on success (or EINPROGRESS).
  bool priv_connect(struct sockaddr* addr,
      size_t rcvbuf_size, size_t sndbuf_size,
      struct sockaddr* bind_addr);

 protected:
  //---------------------------------------------------------------------------
  // Protected methods
  //

  // Connect to internet address `ip', port `port'.
  // The socket receive and send buffer sizes are set to respectively
  // `rcvbuf_size' and `sndbuf_size'. If `rcvbuf_size' is 0 then
  // `minimum_input_size()' is used to determine the receive socket buffer
  // size and if `sndbuf_size' is 0 then `minimum_output_size()' is used
  // to determine the send socket buffer size.
  //
  // Returns true on success (or EINPROGRESS).
  bool priv_in_connect(struct in_addr ip, unsigned short int port,
      size_t rcvbuf_size, size_t sndbuf_size);

  // Connect to internet address `ip', port `port'.
  // Bind to the local interface with address `local_ip'.
  // The socket receive and send buffer sizes are set to respectively
  // `rcvbuf_size' and `sndbuf_size'. If `rcvbuf_size' is 0 then
  // `minimum_input_size()' is used to determine the receive socket buffer
  // size and if `sndbuf_size' is 0 then `minimum_output_size()' is used
  // to determine the send socket buffer size.
  //
  // Returns true on success (or EINPROGRESS).
  bool priv_in_connect(struct in_addr ip, unsigned short int port,
      struct in_addr local_ip,
      size_t rcvbuf_size, size_t sndbuf_size);

#if 0
  // FIXME: host lookup is blocking
  // Connect to remote host `host', port `port'.
  // `host' can be either the hostname of the remote site you want to
  // connect to, or an IP# represented as string. For instance "127.0.0.1".
  // See above for a description of four sizes.
  //
  // Returns true on success (or EINPROGRESS).
  bool priv_in_connect(char const* host, unsigned short int port,
      size_t rcvbuf_size, size_t sndbuf_size);

  // FIXME: host lookup is blocking
  // Connect to remote host `host', port `port'.
  // Bind to the local interface with address `local_ip'.
  // `host' can be either the hostname of the remote site you want to
  // connect to, or an IP# represented as string. For instance "127.0.0.1".
  // See above for a description of four sizes.
  //
  // Returns true on success (or EINPROGRESS).
  bool priv_in_connect(char const* host, unsigned short int port,
      struct in_addr local_ip,
      size_t rcvbuf_size, size_t sndbuf_size);
#endif

  // Connect to Unix domain socket path `path'.
  // See above for a description of rcvbuf_size and sndbuf_size.
  //
  // Returns true on success (or EINPROGRESS).
  bool priv_un_connect(char const* path,
      size_t rcvbuf_size, size_t sndbuf_size);

 protected:
  virtual size_t minimum_input_size() const = 0;
  virtual size_t minimum_output_size() const = 0;

 public:
  // Associate this object with an existing and open socket `fd'.
  void init(int fd, struct sockaddr* addr, size_t rcvbuf_size = 0, size_t sndbuf_size = 0)
  {
#ifdef CWDEBUG
    if (is_open())
      DoutFatal(dc::core, "Trying to `init' a Socket that is already open.");
#endif
    m_addr = addr;
    m_rcvbuf_size = rcvbuf_size;
    m_sndbuf_size = sndbuf_size;
    if (!set_rcvsockbuf(fd, m_rcvbuf_size, minimum_input_size()) ||
	!set_sndsockbuf(fd, m_sndbuf_size, minimum_output_size()))
    {
      // Why does this happen?
      ASSERT(false);
      return;
    }
    IOBase::init(fd);
    start();
  }

 public:
  //---------------------------------------------------------------------------
  // Public accessors:
  //

  // Returns the remote IP number and port that this socket connected with.
  // Only valid when `is_open' returns true.
  SocketAddress address() const { return m_addr; }

  // Returns the local IP number and port of this socket.
  // Only valid when `is_open' returns true.
  SocketAddress local_address() const;

  // Returns a pointer to the bind address if any.
  struct sockaddr const* bind_addr() const { return m_local_addr; }

  // Accessor for m_rcvbuf_size.
  size_t get_rcvbuf_size() const { return m_rcvbuf_size; }

  // Accessor for m_sndbuf_size.
  size_t get_sndbuf_size() const { return m_sndbuf_size; }

  char const* get_path() const
  {
#ifdef CWDEBUG
    if (!m_addr || m_addr->sa_family != AF_UNIX)
      DoutFatal(dc::core, "Calling SocketDevice::get_path for a non AF_UNIX socket");
#endif
    return ((struct sockaddr_un*)m_addr)->sun_path;
  }
};

//=============================================================================
//
// class Socket
//
// Base class for 'connect' SOCKet BUFfers.
//
// SYNOPSIS
//
// This class implements connect() for 'client' sockets buffers.
//

template<class INPUT, class OUTPUT>
class Socket : public SocketDevice, public INPUT, public OUTPUT
{
 protected:
  size_t minimum_input_size() const override { return INPUT::m_ibuffer->minimum_block_size(); }
  size_t minimum_output_size() const override { return OUTPUT::m_obuffer->minimum_block_size(); }

 public:
  //---------------------------------------------------------------------------
  // Constructors
  //
  // After using these constructors, you still have to call `connect' before this object will do anything.
  // Or you can call `init', to associate it with an existing and open socket.

  Socket(typename INPUT::buffer_type* ibuffer, typename OUTPUT::buffer_type* obuffer) :
    INPUT(ibuffer),
    OUTPUT(obuffer)
  {
    Dout(dc::io, "this = " << (void*)this << "; Socket(" << (void*)ibuffer << ", " << (void*)obuffer << ')');
  }

  template<typename IO_with_buflink_type = INPUT>
  Socket(typename IO_with_buflink_type::buflink_type& link_ibuffer, typename OUTPUT::buffer_type* obuffer) :
    INPUT(link_ibuffer->rddbbuf()),
    OUTPUT(obuffer)
  {
    Dout(dc::io, "this = " << (void*)this << "; Socket(" << (void*)link_ibuffer << ", " << (void*)obuffer << ')');
  }

  template<typename IO_with_buflink_type = OUTPUT>
  Socket(typename INPUT::buffer_type* ibuffer, typename IO_with_buflink_type::buflink_type& link_obuffer) :
    INPUT(ibuffer),
    OUTPUT(link_obuffer->rddbbuf())
  {
    Dout(dc::io, "this = " << (void*)this << "; Socket(" << (void*)ibuffer << ", " << (void*)link_obuffer << ')');
  }

  template<typename IO_with_buflink_type1 = INPUT, typename IO_with_buflink_type2 = OUTPUT>
  Socket(typename IO_with_buflink_type1::buflink_type& link_ibuffer, typename IO_with_buflink_type2::buflink_type& link_obuffer) :
    INPUT(link_ibuffer->rddbbuf()),
    OUTPUT(link_obuffer->rddbbuf())
  {
    Dout(dc::io, "this = " << (void*)this << "; Socket(" << (void*)link_ibuffer << ", " << (void*)link_obuffer << ')');
  }

  // The following constructor is added for convenience, it adds its own buffers:

  Socket() :
    INPUT( NEW(typename INPUT::buffer_type(INPUT::default_blocksize_c)) ),
    OUTPUT( NEW(typename OUTPUT::buffer_type(OUTPUT::default_blocksize_c)) )
  {
    Dout(dc::io, "this = " << (void*)this << "; Socket()");
  }

  template<typename INPUT_with_buflink_type = INPUT>
  Socket(typename std::enable_if<std::is_base_of<InputDevice, INPUT_with_buflink_type>::value, typename INPUT_with_buflink_type::buflink_type>::type& link_ibuffer) :
    INPUT(link_ibuffer->rddbbuf()),
    OUTPUT( NEW(typename OUTPUT::buffer_type(OUTPUT::default_blocksize_c)) )
  {
    Dout(dc::io, "this = " << (void*)this << "; Socket(" << (void*)link_ibuffer << ')');
  }

  template<typename OUTPUT_with_buflink_type = OUTPUT>
  Socket(typename std::enable_if<std::is_base_of<OutputDevice, OUTPUT_with_buflink_type>::value, typename OUTPUT_with_buflink_type::buflink_type>::type& link_obuffer) :
    INPUT( NEW(typename INPUT::buffer_type(INPUT::default_blocksize_c)) ),
    OUTPUT(link_obuffer->rddbbuf())
  {
    Dout(dc::io, "this = " << (void*)this << "; Socket(" << (void*)link_obuffer << ')');
  }

 public:
  //---------------------------------------------------------------------------
  // Public methods
  //

  // See `SocketDevice' for a description.
  bool connect(
      struct in_addr ip, unsigned short int port,
      size_t rcvbuf_size = 0, size_t sndbuf_size = 0
      )
  {
    return priv_in_connect(ip, port, rcvbuf_size, sndbuf_size);
  }

  // See `SocketDevice' for a description.
  bool connect(
      struct in_addr ip, unsigned short int port,
      struct in_addr local_ip,
      size_t rcvbuf_size = 0, size_t sndbuf_size = 0)
  {
    return priv_in_connect(ip, port, local_ip, rcvbuf_size, sndbuf_size);
  }

#if 0
  // See `SocketDevice' for a description.
  bool connect(
      char const* host, unsigned short int port,
      size_t rcvbuf_size = 0, size_t sndbuf_size = 0)
  {
    return priv_in_connect(host, port, rcvbuf_size, sndbuf_size);
  }

  // See `SocketDevice' for a description.
  bool connect(
      char const* host, unsigned short int port,
      struct in_addr local_ip,
      size_t rcvbuf_size = 0, size_t sndbuf_size = 0)
  {
    return priv_in_connect(host, port, local_ip, rcvbuf_size, sndbuf_size);
  }
#endif

  // See `SocketDevice' for a description.
  bool connect(
      char const* path,
      size_t rcvbuf_size = 0, size_t sndbuf_size = 0)
  {
    return priv_un_connect(path, rcvbuf_size, sndbuf_size);
  }
};

} // namespace evio
