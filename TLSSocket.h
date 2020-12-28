/**
 * evio -- A cwm4 git submodule for adding support for buffered, iostream oriented, epoll based I/O.
 *
 * @file
 * @brief Declaration of class TLSSocket.
 *
 * @Copyright (C) 2019  Carlo Wood.
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

#include "evio/Socket.h"
#include "evio/protocol/TLS.h"
#include "evio/Source.h"
#include "evio/Sink.h"

namespace evio {

class TLSSocket : public Socket
{
 private:
  protocol::TLS m_tls;
  uint32_t m_max_frag;
  static constexpr uint32_t s_max_frag_magic = 0x4001;  // Must be one larger than the maximum allowed SSL fragment size of 0x4000.
  std::string m_ServerNameIndication;

 public:
#ifdef DEBUGDEVICESTATS
  TLSSocket() : m_tls(m_sent_bytes, m_received_bytes) { }
#endif

  bool connect(SocketAddress const& socket_address, std::string const& ServerNameIndication = {}, size_t rcvbuf_size = 0, size_t sndbuf_size = 0, SocketAddress const& if_addr = {})
  {
    tls_init(socket_address, ServerNameIndication);
    bool in_progress = evio::Socket::connect(socket_address, rcvbuf_size, sndbuf_size, if_addr);
    if (in_progress)
    {
      // We want to write the TLS client hello message, but Socket::connect() might not have started the output device.
      start_output_device();
    }
    return in_progress;
  }

  void init(int fd, SocketAddress const& socket_address, std::string const& ServerNameIndication = {})
  {
    tls_init(socket_address, ServerNameIndication);
    evio::Socket::init(fd, socket_address);
    // We need to write the TLS client hello message so make sure the device is started.
    start_output_device(state_t::wat(m_state));
  }

  void write_to_fd(int& allow_deletion_count, int fd) override;
  void read_from_fd(int& allow_deletion_count, int fd) override;

 private:
  void fd_init(int fd, bool make_non_blocking) override;                // Called after FileDescriptor::m_fd is set, but before the device is started.
  void set_sni(std::string const& ServerNameIndication) override;
  void tls_init(SocketAddress const& socket_address, std::string const& ServerNameIndication);
  bool handshake_completed() const { return m_max_frag < s_max_frag_magic; }

 protected:
  int sync() override;
};

} // namespace evio
