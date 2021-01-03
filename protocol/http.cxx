#include "sys.h"
#include "http.h"
#include <charconv>
#ifdef CWDEBUG
#include "utils/debug_ostream_operators.h"
#endif

namespace evio {
namespace protocol {
namespace http {

std::streamsize MessageDecoder::end_of_msg_finder(char const* new_data, size_t rlen)
{
  DoutEntering(dc::io, "http::MessageDecoder::end_of_msg_finder(..., " << rlen << ")");
  // Even when m_state == message_header_field_name we still have to detect empty lines.
  if (m_state == message_header_field_name && AI_UNLIKELY(*new_data == '\r'))
  {
    m_state = empty_line;
    return (rlen > 1 && new_data[1] == '\n') ? 2 : 0;
  }
  else if (m_state == body)
  {
    return m_content_length == -1 ? rlen : 0;
  }
  char eom_char = m_state == message_header_field_name ? ':' : '\n';
  char const* eom = static_cast<char const*>(std::memchr(new_data, eom_char, rlen));
  return eom ? eom - new_data + 1 : 0;
}

void MessageDecoder::decode(int& allow_deletion_count, evio::MsgBlock&& msg)
{
  DoutEntering(dc::notice, "http::MessageDecoder::decode({" << allow_deletion_count << "}, " << msg << ") [" << this << ']');
  try
  {
    switch (m_state)
    {
      case start_line:
        decode_start_line(msg);
        m_state = message_header_field_name;
        break;
      case message_header_field_name:
        msg.remove_suffix(1);   // Remove trailing ':'.
        process_header_field_name(std::move(msg));
        m_state = message_header_value_name;
        break;
      case message_header_value_name:
      {
        int count = 0;
        for (char const* ptr = msg.get_start(); ptr != msg.get_end(); ++ptr)
          if (*ptr == ' ' || *ptr == '\t')
            ++count;
          else
            break;
        msg.remove_prefix(count);               // Remove leading OWS.
        // The new-line is already guaranteed by end_of_msg_finder.
        if (msg.get_size() < 2 || msg.get_end()[-2] != '\r')
          THROW_ALERT("Ill-formed EOL in header.");
        count = 2;
        for (char const* ptr = msg.get_end() - count; --ptr >= msg.get_start();)
          if (*ptr == ' ' || *ptr == '\t')
            ++count;
          else
            break;
        msg.remove_suffix(count);               // Remove trailing OWS CR LF
        process_header_value_name(std::move(msg));
        m_state = message_header_field_name;
        break;
      }
      case empty_line:
        {
          // Release m_current_header_field.
          evio::MsgBlock tmp(std::move(m_current_header_field));
        }
        if (msg.get_size() != 2)
        {
          Dout(dc::warning, "Received an invalid header line.");  // Heh - something like "\r...\n" where ... is non-empty.
          close_input_device(allow_deletion_count);
          return;
        }
        Dout(dc::notice, "Received empty line. Content-Length is " << m_content_length);
        // Switch decoder.
        if (m_content_type_to_decoder_index == -1)
        {
          if (m_content_length != 0)
            THROW_ALERT("No matching Content-Type found. Can not decode body of length [LENGTH]", AIArgs("[LENGTH]", m_content_length));
          close_input_device(allow_deletion_count);
        }
        else
        {
          m_state = body;
          switch_protocol_decoder(m_content_type_to_decoder_map[m_content_type_to_decoder_index].second);
        }
        break;
      case body:
        for (auto&& p : m_headers)
          Dout(dc::notice, p.first << " : " << p.second);
        m_headers.clear();
        close_input_device(allow_deletion_count);
        break;
    }
  }
  catch (AIAlert::Error const& error)
  {
    Dout(dc::warning, error);
    close_input_device(allow_deletion_count);
  }
}

void MessageDecoder::process_header_field_name(evio::MsgBlock&& msg)
{
  DoutEntering(dc::notice, "http::MessageDecoder::process_header_field_name(" << msg << ")");
  m_current_header_field = std::move(msg);
}

void MessageDecoder::process_header_value_name(evio::MsgBlock&& msg)
{
  DoutEntering(dc::notice, "http::MessageDecoder::process_header_value_name(" << msg << ")");
  if (m_current_header_field.view() == "Content-Length")
  {
    auto result = std::from_chars(msg.get_start(), msg.get_end(), m_content_length);
    if (result.ec == std::errc::invalid_argument || result.ptr != msg.get_end() || m_content_length < 0)
    {
      m_content_length = -1;
      THROW_ALERTC(result.ec, "Content-Length header with invalid value [[VIEW]]", AIArgs("[VIEW]", m_current_header_field.view()));
    }
  }
  else if (m_current_header_field.view() == "Content-Type")
  {
    for (int i = 0; i < m_content_type_to_decoder_map.size(); ++i)
      if (m_content_type_to_decoder_map[i].first == msg.view())
      {
        Dout(dc::notice, "Found match.");
        m_content_type_to_decoder_index = i;
        break;
      }
  }
  m_headers.emplace_back(std::move(m_current_header_field), std::move(msg));
}

void ResponseHeadersDecoder::decode_start_line(evio::MsgBlock const& msg)
{
  // Just print what was received.
  DoutEntering(dc::notice, "http::ResponseHeadersDecoder::decode_start_line(" << msg << ") [" << this << ']');

  // This is the first line of a Response Message.
  //
  // If the start line doesn't match the required response then that is an error,
  // otherwise we have the status line.
  //
  // The required form is (RFC7230):
  //
  // status-line  = HTTP-version SP status-code SP reason-phrase CRLF
  // HTTP-version = HTTP-name "/" DIGIT "." DIGIT
  // HTTP-name    = %x48.54.54.50 ; "HTTP", case-sensitive
  // status-code  = 3DIGIT
  // reason-phrase  = *( HTAB / SP / VCHAR / obs-text )
  // obs-text       = %x80-FF
  //
  // Where (RFC5234):
  // DIGIT          = %x30-39 ; 0-9
  // HTAB           = %x09 ; horizontal tab
  // SP             = %x20
  // VCHAR          = %x21-7E ; visible (printing) characters
  // CRLF           =  CR LF ; Internet standard newline
  // CR             =  %x0D ; carriage return
  // LF             =  %x0A ; linefeed

  // Hence the string must look like:
  //
  //     HTTP/1.1 200 <reason-phrase>\r\n
  //
  // and thus have a length of at least 15 characters.
  //
  char const* ptr = msg.get_start();
  if (msg.get_size() < 15)
    m_protocol_error = true;
  else if (strncmp(ptr, "HTTP/1.", 7) != 0)
    m_protocol_error = true;
  else
  {
    ptr += 7;
    if (*ptr != '0' && *ptr != '1' || ptr[1] != ' ')
      m_protocol_error = true;
    else
    {
      m_http_minor = *ptr - '0';
      ptr += 2;
      for (int digitn = 0; digitn < 3; ++digitn)
      {
        int digit = *ptr++ - '0';
        if (digit < 0 || digit > 9)
        {
          m_protocol_error = true;
          break;
        }
        m_status_code = 10 * m_status_code + digit;
      }
      if (*ptr++ != ' ')
        m_protocol_error = true;
      else
      {
        int reason_phrase_length = msg.get_size() - (ptr - msg.get_start()) - 2;
        for (int reason_phrase_charn = 0; reason_phrase_charn < reason_phrase_length; ++reason_phrase_charn)
        {
          // reason_phrase_char.
          unsigned char rpc = *ptr++;
          if (rpc != 0x09 && rpc != 0x20 && !(0x21 <= rpc && rpc <= 0x7e) && !(0x80 <= rpc /* && rpc <= 0xff */))
          {
            m_protocol_error = true;
            break;
          }
#ifdef CWDEBUG
          m_reason_phrase += rpc;
#endif
        }
        if (*ptr != '\r' || ptr[1] != '\n')
          m_protocol_error = true;
      }
    }
  }

  if (m_protocol_error || m_status_code != 200)
  {
    if (m_protocol_error)
      THROW_ALERT("Invalid HTTP status-line");
    THROW_ALERT("Received status code [STATUS_CODE] [REASON_PHRASE]", AIArgs("[STATUS_CODE]", m_status_code)("[REASON_PHRASE]", m_reason_phrase));
  }
}

} // namespace http
} // namespace protocol
} // namespace evio
