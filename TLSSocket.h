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
  bool connect(SocketAddress const& remote_address, std::string const& ServerNameIndication = {}, size_t rcvbuf_size = 0, size_t sndbuf_size = 0, SocketAddress const& if_addr = {})
  {
    if (!ServerNameIndication.empty())
      m_ServerNameIndication = ServerNameIndication;
    else
    {
      // Just pass an SIN.
      ASSERT(remote_address.is_ip());
      m_ServerNameIndication = remote_address.to_string(true);
    }
    m_tls.set_device(this, this);
    m_output_state = preconnect_out;
    m_max_frag = s_max_frag_magic;
    int ret = evio::Socket::connect(remote_address, rcvbuf_size, sndbuf_size, if_addr);
    return ret;
  }

  void write_to_fd(int& allow_deletion_count, int fd) override;
  void read_from_fd(int& allow_deletion_count, int fd) override;
  void data_received(int& allow_deletion_count, char const* new_data, size_t rlen) override;

 private:
  bool handshake_completed() const { return m_max_frag != s_max_frag_magic; }

 protected:
  int sync() override;
};

} // namespace evio
