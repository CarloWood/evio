#pragma once

#include <mutex>
#include "evio/FileDescriptor.h"
#include "evio/Source.h"
#include "evio/Sink.h"
#include "evio/SocketAddress.h"
//#include <gnutls/gnutls.h>
#include "matrixsslApi.h"
#include "debug.h"
#include <libcwd/buf2str.h>

#if defined(CWDEBUG) && !defined(DOXYGEN)
NAMESPACE_DEBUG_CHANNELS_START
extern channel_ct gnutls;
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
  static void global_tls_initialization();
//  static gnutls_certificate_credentials_t s_xcred;
  static int s_debug_level;

  boost::intrusive_ptr<InputDevice> m_input_device;     // The underlaying input device.
  boost::intrusive_ptr<OutputDevice> m_output_device;   // The underlaying output device.
  TLSSink m_tls_sink;                                   // The sink that the underlaying input device should use.
  TLSSource m_tls_source;                               // The source that the underlaying output device should use.
//  gnutls_session_t m_session;                           // Session state.
//  gnutls_datum_t m_rdata;                               // Resumption data.

 public:
  TLS();
  ~TLS();

#if 0
  // The level is an integer between 0 and 9. Higher values mean more verbosity.
  // The default value is 0.
  //
  // Larger values should only be used with care, since they may reveal sensitive information.
  //
  // See https://gnutls.org/manual/html_node/Core-TLS-API.html#gnutls_005fglobal_005fset_005flog_005flevel
  static void set_debug_level(int debug_level);

  void set_device(InputDevice* input_device, OutputDevice* output_device)
  {
    DoutEntering(dc::evio, "TLS::set_device(" << input_device << ", " << output_device << ")");
    m_input_device = input_device;
    m_output_device = output_device;
    input_device->set_sink(m_tls_sink);
    output_device->set_source(m_tls_source);
  }
#endif

  void session_init(char const* http_server_name, size_t http_server_name_length);
  void session_init(SocketAddress const& remote_address)
  {
    // Use session_init(char const* http_server_name) instead.
    ASSERT(remote_address.is_ip());
    std::string http_server_name = remote_address.to_string(true);
    session_init(http_server_name.c_str(), http_server_name.length());
  }
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
