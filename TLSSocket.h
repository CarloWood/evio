#include "evio/Socket.h"
#include "evio/protocol/TLS.h"
#include "evio/Source.h"
#include "evio/Sink.h"

namespace evio {

class TLSSocket : public Socket
{
 private:
  protocol::TLS m_tls;

 public:
  void set_source(Source const&)
  {
  }

  void set_sink(Sink const&)
  {
  }

  bool connect(SocketAddress const& remote_address, size_t rcvbuf_size = 0, size_t sndbuf_size = 0, SocketAddress const& if_addr = {})
  {
    m_tls.set_device(this, this);
    int ret = evio::Socket::connect(remote_address, rcvbuf_size, sndbuf_size, if_addr);
    return ret;
  }

//        connected(allow_deletion_count, true); // Signal successful connect.

  void write_to_fd(int& allow_deletion_count, int fd) override;
  void read_from_fd(int& allow_deletion_count, int fd) override;
};

} // namespace evio
