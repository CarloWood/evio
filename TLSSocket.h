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
  static constexpr int outdata_ready = 1;
  static constexpr int stopped = 2;
  static constexpr int post_handshake = 4;

 public:
  enum output_state_type {
    preconnect_out =            0,                                              // We're not connected yet.
    handshake_OutData_ready =                              outdata_ready,       // We must call matrixSslGetOutdata to retrieve encrypted data part of the handshake that must be sent to the peer.
    handshake_idle_out =                         stopped | outdata_ready,       // All encrypted data was written, stream was stopped.
    encode_app_data =           post_handshake,                                 // Handshake finished, call ... to encrypt application data.
    OutData_ready =             post_handshake |           outdata_ready,       // We must call matrixSslGetOutdata the encrypted application data that must be sent to the peer.
    write_error_out =           post_handshake | stopped,                       // A write error occurred.
    idle_out =                  post_handshake | stopped | outdata_ready        // All encrypted data was written, stream was stopped (post handshake).
  };

  static char const* output_state_to_str(output_state_type output_state);

 private:
  protocol::TLS m_tls;
  std::mutex m_output_state_mutex;
  std::atomic<output_state_type> m_output_state;
  uint32_t m_max_frag;
  static constexpr uint32_t s_max_frag_magic = 0x5000;  // Must be larger than 0x4000.
  std::string m_ServerNameIndication;

 public:
  bool connect(SocketAddress const& socket_address, std::string const& ServerNameIndication = {}, size_t rcvbuf_size = 0, size_t sndbuf_size = 0, SocketAddress const& if_addr = {})
  {
    tls_init(socket_address, ServerNameIndication);
    return evio::Socket::connect(socket_address, rcvbuf_size, sndbuf_size, if_addr);
  }

  void init(int fd, SocketAddress const& socket_address, std::string const& ServerNameIndication = {})
  {
    tls_init(socket_address, ServerNameIndication);
    evio::Socket::init(fd, socket_address);
  }

  void write_to_fd(int& allow_deletion_count, int fd) override;
  void read_from_fd(int& allow_deletion_count, int fd) override;
  void data_received(int& allow_deletion_count, char const* new_data, size_t rlen) override;

 private:
  void set_sni(std::string const& ServerNameIndication) override;
  void tls_init(SocketAddress const& socket_address, std::string const& ServerNameIndication);
  bool handshake_completed() const { return m_max_frag != s_max_frag_magic; }

 protected:
  int sync() override;
};

} // namespace evio
