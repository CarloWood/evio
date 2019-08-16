#pragma once

#include <mutex>
#include "evio/FileDescriptor.h"
#include "evio/Source.h"
#include "evio/Sink.h"
#include "evio/SocketAddress.h"
#include "debug.h"
#include <libcwd/buf2str.h>

#if defined(CWDEBUG) && !defined(DOXYGEN)
NAMESPACE_DEBUG_CHANNELS_START
extern channel_ct tls;
NAMESPACE_DEBUG_CHANNELS_END
#endif

namespace evio {

namespace protocol {

struct TLSSource : public Source
{
 protected:
  OutputBuffer* create_buffer(OutputDevice* output_device, size_t buffer_full_watermark, size_t max_alloc) override
  {
    DoutEntering(dc::evio, "TLSSource::create_buffer(" << output_device << ", " << buffer_full_watermark << ", " << max_alloc << ")");
    m_output_device = output_device;
    OutputBuffer* output_buffer = new OutputBuffer(output_device, minimum_block_size(), buffer_full_watermark, max_alloc);
    return output_buffer;
  }
};

struct TLSSink : public InputDecoder
{
  size_t end_of_msg_finder(const char*, size_t) override
  {
    DoutEntering(dc::evio, "TLSSink::end_of_msg_finder()");
    return 0;
  }

  void decode(int& allow_deletion_count, MsgBlock&& msg) override
  {
    DoutEntering(dc::evio, "TLSSink::decode({" << allow_deletion_count << ", {MsgBlock:" << libcwd::buf2str(msg.get_start(), msg.get_size()) << "})");
  }
};

class TLS
{
 private:
  static std::once_flag s_flag;
  static std::string get_CA_files();                    // Returns a semi-colon separated list of all trusted CA certificate bundles that we could find.
  static void global_tls_initialization();
  static void global_tls_deinitialization();
  static int s_debug_level;

  boost::intrusive_ptr<InputDevice> m_input_device;     // The underlaying input device.
  boost::intrusive_ptr<OutputDevice> m_output_device;   // The underlaying output device.
  TLSSink m_tls_sink;                                   // The sink that the underlaying input device should use.
  TLSSource m_tls_source;                               // The source that the underlaying output device should use.
  void* m_session;                                      // ssl_t* m_session; Session state.
  void* m_session_opts;                                 // sslSessOpts_t* m_session_opts; Session options.
  void* m_session_id;                                   // sslSessionId_t* m_session_id; Session resume data.

  // Accessor for m_session.
  inline auto const session() const;                    // Returns a ssl_t* const.

  // Accessor for m_session_opts.
  inline auto const session_opts() const;               // Returns a sslSessOpts_t* const.

  // Accessor for m_session_id.
  inline auto const session_id() const;                 // Returns a sslSessionId_t* const.

 public:
  TLS();
  ~TLS();

  void set_device(InputDevice* input_device, OutputDevice* output_device)
  {
    DoutEntering(dc::evio, "TLS::set_device(" << input_device << ", " << output_device << ")");
    m_input_device = input_device;
    m_output_device = output_device;
    input_device->set_sink(m_tls_sink);
    output_device->set_source(m_tls_source);
  }

  void session_init(char const* http_server_name);
  void session_init(SocketAddress const& remote_address)
  {
    // Use session_init(char const* http_server_name) instead.
    ASSERT(remote_address.is_ip());
    std::string http_server_name = remote_address.to_string(true);
    session_init(http_server_name.c_str());
  }

  enum data_result_type
  {
    SUCCESS,
    REQUEST_SEND,
    REQUEST_RECV,
    REQUEST_CLOSE,
    HANDSHAKE_COMPLETE,
    RECEIVED_ALERT_WARNING,
    RECEIVED_ALERT_FATAL,
    APP_DATA,
    APP_DATA_COMPRESSED
  };

  // Called from TLSSocket::write_to_fd.
  int32_t matrixSslGetOutdata(char** buf_ptr);
  data_result_type matrixSslSentData(ssize_t wlen);
  // Called from TLSSocket::read_from_fd.
  int32_t matrixSslGetReadbuf(char** buf_ptr);
  data_result_type matrixSslReceivedData(ssize_t rlen, char** buf_ptr, uint32_t* buf_len_ptr);
  data_result_type matrixSslProcessedData(char** buf_ptr, uint32_t* buf_len_ptr);
};

enum error_codes
{
};

std::error_code make_error_code(error_codes);

} // namespace protocol
} // namespace evio

// Register evio::error_codes as valid error code.
namespace std {

template<> struct is_error_code_enum<evio::protocol::error_codes> : true_type { };

} // namespace std
