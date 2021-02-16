#pragma once

#include "Decoder.h"
#include "evio/StreamBuf.h"
#include <string>
#include <utility>
#include <vector>

namespace evio {
namespace protocol {
namespace http {

// Coded while reading https://www.w3.org/Protocols/rfc2616/rfc2616-sec4.html#sec4.1
//
class MessageDecoder : public evio::protocol::Decoder
{
 public:
  // The highest protocol that we understand.
  static constexpr int s_http_major = 1;
  static constexpr int s_http_minor = 1;

  // The states that we can be in.
  enum state_st {
    start_line,
    message_header_field_name,
    message_header_value_name,
    empty_line,
    body
  };

 private:
  state_st m_state;
  std::vector<std::pair<std::string, evio::Sink&>> m_content_type_to_decoder_map;
  evio::MsgBlock m_current_header_field;
  std::vector<std::pair<evio::MsgBlock, evio::MsgBlock>> m_headers;   // Field, Value pairs.
  int m_content_length;
  int m_content_type_to_decoder_index;

 public:
  MessageDecoder(std::vector<std::pair<std::string, evio::Sink&>> content_type_to_decoder_map = {}) :
    m_content_type_to_decoder_map(std::move(content_type_to_decoder_map)),
    m_content_type_to_decoder_index(-1), m_state(start_line), m_current_header_field(nullptr, 0), m_content_length(-1) { }

  void add(std::pair<std::string, evio::protocol::Decoder&> content_type_decoder_pair)
  {
    m_content_type_to_decoder_map.push_back(content_type_decoder_pair);
  }

  // This is called by m_content_type_to_decoder_map[m_content_type_to_decoder_index].second.
  int content_length() const { return m_content_length; }

 protected:
  size_t end_of_msg_finder(char const* new_data, size_t rlen, EndOfMsgFinderResult& result) override;
  void decode(int& allow_deletion_count, evio::MsgBlock&& msg) override;
  void process_header_field_name(evio::MsgBlock&& msg);
  void process_header_value_name(evio::MsgBlock&& msg);

  // Throws upon failure.
  virtual void decode_start_line(evio::MsgBlock const& msg) = 0;
};

// Accept HTTP Response input of the form:
//
// HTTP/1.1 200 OK
// Some-Header: its, value=here
// ...
//
// Usage:
//
// BodyDecoder body_decoder;                    // Derived from evio::protocol/Decoder.
// ResponseHeadersDecoder http_decoder(
//      {{"application/xml", body_decoder}}     // Pass a vector of Content-Type, decoder pairs.
//   );
//
// socket.set_protocol_decoder(http_decoder);   // Or whatever InputDevice is being used.
//
class ResponseHeadersDecoder : public MessageDecoder
{
 private:
  // We only understand major version 1.
  int m_http_minor;     // 0 or 1.
  bool m_protocol_error;
  int m_status_code;
#ifdef CWDEBUG
  std::string m_reason_phrase;
#endif

 public:
  // Until the server tells us otherwise, we have to speak verion 1.0.
  // m_http_minor is updated at the moment that m_state != start_line.
  ResponseHeadersDecoder(std::vector<std::pair<std::string, evio::Sink&>> args) :
    MessageDecoder(args), m_http_minor(0), m_protocol_error(false), m_status_code(0) { }

  // Most HTML header lines are very short (in the order of 32 bytes or less),
  // but some header lines, most notably cookies can be rather long (say, 300 bytes).
  // Specifying values of up to 512 bytes have no negative impact, so lets use
  // something on the larger side (so that > 99.9% of the headers will fit
  // in the allocated buffer that will be 6 times as large, or 1536 bytes.
  size_t average_message_length() const override { return 256; }

  // Accessor for m_status_code. Should be 200 when successful.
  int get_status_code() const { return m_status_code; }

 protected:
  void decode_start_line(evio::MsgBlock const& msg) override;
};

} // namespace http
} // namespace protocol
} // namespace evio
