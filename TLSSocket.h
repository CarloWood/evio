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
  // SLL session state bits.
  static constexpr int want_write = 1;
  static constexpr int want_read = 2;
  static constexpr int stopped = 4;             // Output device was stopped.
  static constexpr int post_handshake = 8;

 public:
  enum session_state_type {
    preconnect =                0,                                       // We're not connected yet.
    handshake_want_write =                                  want_write,  // We must call m_tls.do_handshake() when the socket is writable.
    handshake_want_read =                        want_read,              // We must call m_tls.do_handshake() when the socket is readable.
    app_want_write =            post_handshake |            want_write,  // We must call m_tls.do_write when the socket is writable.
    app_idle_out =              post_handshake | want_read,              // All encrypted data was written, stream was stopped (post handshake).
    app_write_error =           post_handshake ,                         // A write error occurred.
  };

  static char const* session_state_to_str(session_state_type session_state);
  static bool is_post_handshake(session_state_type session_state) { return session_state & post_handshake; }
  static bool is_stopped(session_state_type session_state) { return session_state & stopped; }

 private:
  protocol::TLS m_tls;
  std::mutex m_session_state_mutex;
  std::atomic<session_state_type> m_session_state;
  uint32_t m_max_frag;
  static constexpr uint32_t s_max_frag_magic = 0x5000;  // Must be larger than 0x4000.
  std::string m_ServerNameIndication;

 public:
  bool connect(SocketAddress const& socket_address, std::string const& ServerNameIndication = {}, size_t rcvbuf_size = 0, size_t sndbuf_size = 0, SocketAddress const& if_addr = {})
  {
    tls_init(socket_address, ServerNameIndication);
    bool in_progress = evio::Socket::connect(socket_address, rcvbuf_size, sndbuf_size, if_addr);
    if (in_progress)
    {
      // We want to write the TLS client hello message, but Socket::connect() didn't start
      // the output device because our output buffer is empty (since that is used for plain text
      // app data).
      start_output_device(state_t::wat(m_state));
    }
    return in_progress;
  }

  void init(int fd, SocketAddress const& socket_address, std::string const& ServerNameIndication = {})
  {
    tls_init(socket_address, ServerNameIndication);
    evio::Socket::init(fd, socket_address);
    // Since this function is not calling start_output_device (see connect),
    // the TLS handshake is delayed until we try to write app data.
  }

  void write_to_fd(int& allow_deletion_count, int fd) override;
  void read_from_fd(int& allow_deletion_count, int fd) override;
  void data_received(int& allow_deletion_count, char const* new_data, size_t rlen) override;

 private:
  void fd_init(int fd, bool make_non_blocking) override;                // Called after FileDescriptor::m_fd is set, but before the device is started.
  void set_sni(std::string const& ServerNameIndication) override;
  void tls_init(SocketAddress const& socket_address, std::string const& ServerNameIndication);
  bool handshake_completed() const { return m_max_frag != s_max_frag_magic; }

 protected:
  int sync() override;
};

} // namespace evio
