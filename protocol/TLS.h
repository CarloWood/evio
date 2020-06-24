/**
 * evio -- A cwm4 git submodule for adding support for buffered, iostream oriented, epoll based I/O.
 *
 * @file
 * @brief Declarations of classes TLSSource, TLSSink and TLS.
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

#pragma once

#include "evio/FileDescriptor.h"
#include "evio/Source.h"
#include "evio/Sink.h"
#include "evio/SocketAddress.h"
#include "debug.h"
#include <mutex>
#include <vector>
#ifdef CWDEBUG
#include <libcwd/buf2str.h>
#endif

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

  void decode(int& CWDEBUG_ONLY(allow_deletion_count), MsgBlock&& CWDEBUG_ONLY(msg)) override
  {
    DoutEntering(dc::evio, "TLSSink::decode({" << allow_deletion_count << ", {MsgBlock:" << libcwd::buf2str(msg.get_start(), msg.get_size()) << "})");
  }
};

class TLS
{
 public:
  class WolfSSL_Cleanup;

 private:
  static std::once_flag s_flag;
  static std::vector<std::string> get_CA_files();       // Returns a trusted CA certificate bundle.
  static void global_tls_initialization();
  static void global_tls_deinitialization() noexcept;
  static std::string session_error_string(int session_error);     // Return a descriptive string for the last error on the session.

  boost::intrusive_ptr<InputDevice> m_input_device;     // The underlaying input device.
  boost::intrusive_ptr<OutputDevice> m_output_device;   // The underlaying output device.
  void* m_session;                                      // WOLFSSL* m_session; Session configuration and state.
//  void* m_session_opts;                                 // sslSessOpts_t* m_session_opts; Session options.
//  void* m_session_id;                                   // sslSessionId_t* m_session_id; Session resume data.

  // Accessor for m_session.
  inline auto session() const;                          // Returns a WOLFSSL* const.

#if 0
  // Accessor for m_session_opts.
  inline auto session_opts() const;                     // Returns a sslSessOpts_t* const.

  // Accessor for m_session_id.
  inline auto session_id() const;                       // Returns a sslSessionId_t* const.
#endif

 public:
  TLS();
  ~TLS();

  void set_device(InputDevice* input_device, OutputDevice* output_device)
  {
    DoutEntering(dc::evio, "TLS::set_device(" << input_device << ", " << output_device << ")");
    m_input_device = input_device;
    m_output_device = output_device;
  }

  void session_init(std::string const& ServerNameIndication);
  void set_fd(int fd);

  enum result_type
  {
    HANDSHAKE_WANT_WRITE,
    HANDSHAKE_WANT_READ,
    HANDSHAKE_COMPLETE
#if 0
    SUCCESS,
    REQUEST_SEND,
    REQUEST_RECV,
    REQUEST_CLOSE,
    HANDSHAKE_COMPLETE,
    RECEIVED_ALERT_WARNING,
    RECEIVED_ALERT_FATAL,
    APP_DATA,
    APP_DATA_COMPRESSED
#endif
  };

  result_type do_handshake();

#if 0
  // Called from TLSSocket::write_to_fd.
  int32_t matrixSslGetOutdata(char** buf_ptr);
  data_result_type matrixSslSentData(ssize_t wlen);
  // Called from TLSSocket::read_from_fd.
  int32_t matrixSslGetReadbuf(char** buf_ptr);
  data_result_type matrixSslReceivedData(ssize_t rlen, char const** buf_ptr, uint32_t* buf_len_ptr);
  data_result_type matrixSslProcessedData(char const** buf_ptr, uint32_t* buf_len_ptr);
  int32_t matrixSslEncodeToOutdata(char* buf, uint32_t len);
  uint32_t get_max_frag() const;
#endif
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
