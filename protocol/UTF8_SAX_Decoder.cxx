#include "sys.h"
#include "UTF8_SAX_Decoder.h"
#include "debug.h"
#include <cstring>
#include <iostream>

namespace evio {
namespace protocol {

size_t UTF8_SAX_Decoder::end_of_msg_finder(char const* new_data, size_t rlen, evio::EndOfMsgFinderResult& UNUSED_ARG(result))
{
  DoutEntering(dc::endofmsg|continued_cf, "UTF8_SAX_Decoder::end_of_msg_finder(..., " << rlen << ") = ");
  // ASCII bytes (< 128) do not occur when encoding non-ASCII code points into UTF-8 (all extension bytes are >= 128).
  // It is therefore safe to simply search byte for byte for a '>'.
  char const* right_angle_bracket = static_cast<char const*>(memchr(new_data, '>', rlen));
  size_t found_len = right_angle_bracket ? right_angle_bracket - new_data + 1 : 0;
  Dout(dc::finish, found_len);
  return found_len;
}

int UTF8_SAX_Decoder::add_new_unique_element(std::string&& name)
{
  int element_id = m_unique_elements.size();
  m_unique_elements.emplace_back(element_id, std::move(name));
  // The std::string const& returned by name() is not invalidated by a subsequent m_unique_elements.emplace_back because m_unique_elements is a std::deque.
  m_elements.emplace(m_unique_elements[element_id].name(), element_id);
  return element_id;
}

void UTF8_SAX_Decoder::register_element_id(int element_id, std::string name)
{
  DoutEntering(dc::decoder, "UTF8_SAX_Decoder::register_element_id(" << element_id << ", \"" << name << "\")");
  // register_element_id must be called with increasing id's, starting at 0 and incrementing id with 1 for each call.
  ASSERT(m_unique_elements.size() == element_id);
  add_new_unique_element(std::move(name));
  // This is the whole point of doing this.
  ASSERT(m_unique_elements[element_id].id() == element_id);
}

UTF8_SAX_Decoder::element_id_type UTF8_SAX_Decoder::get_element_id(std::string_view name)
{
  // The name passed might still end on zero or more spaces.
  while (name.back() == ' ')
  {
    name.remove_suffix(1);
    if (name.empty())
      THROW_FALERT("Empty name");
  }
  auto iter = m_elements.find(name);
  if (AI_LIKELY(iter != m_elements.end()))      // Likely because the whole idea is that we find previously used elements, often.
    return iter->second;

  return add_new_unique_element(std::string(name));
}

void UTF8_SAX_Decoder::decode(int& allow_deletion_count, evio::MsgBlock&& msg)
{
  DoutEntering(dc::decoder, "UTF8_SAX_Decoder::decode({" << allow_deletion_count << "}, " <<  msg << ")");

  char const* const data = msg.get_start();
  size_t const len = msg.get_size();

  // decode should never be called with an empty msg.
  ASSERT(len > 0);

  using ParseError = std::exception;
  try
  {
    if (data[0] == '<')
    {
      // The minimum message is "<n>".
      if (len < 3)
        throw ParseError{};
      if (m_document_begin)
      {
        m_document_begin = false;
        // <?xml version="1.0" encoding="utf-8"?>
        if (len < 8 || strncmp(data, "<?xml ", 6) != 0 || strncmp(data + len - 2, "?>", 2) != 0)
          throw ParseError{};
        char const* attributes = data + 6;
        while (*attributes == ' ')
          ++attributes;
        // FIXME
        std::string version;
        std::string encoding;
        start_document(m_content_length, version, encoding);
        return;
      }
      if (data[1] == '/')
      {
        // </n>
        end_element(get_element_id({&data[2], len - 3}));
      }
      else
      {
        // <n> or <n/>.
        bool empty_tag = data[len - 2] == '/';
        element_id_type element_id = get_element_id({&data[1], len - (empty_tag ? 3 : 2)});
        start_element(element_id);
        if (empty_tag)
          end_element(element_id);
      }
    }
    else
    {
      char const* left_angle_bracket = static_cast<char const*>(memchr(data, '<', len));
      size_t end_tag_length;
      if (AI_UNLIKELY(!left_angle_bracket ||
          (end_tag_length = len - (left_angle_bracket - data)) < 4 ||
          left_angle_bracket[1] != '/'))        // 4 is the length of the minimal size of the end element: </n>.
        throw ParseError{};
      size_t characters_len = left_angle_bracket - data;
      characters({data, characters_len});
      // </n>
      end_element(get_element_id({&left_angle_bracket[2], end_tag_length - 3}));
    }
  }
  catch (AIAlert::Error const& error)
  {
    THROW_FALERT("Parse error decoding \"[DATA]\"", AIArgs("[DATA]", msg), error);
  }
  catch (ParseError const&)
  {
    THROW_FALERT("Parse error decoding \"[DATA]\"", AIArgs("[DATA]", msg));
  }
}

void UTF8_SAX_Decoder::end_of_content(int& CWDEBUG_ONLY(allow_delection_count))
{
  DoutEntering(dc::decoder, "UTF8_SAX_Decoder::end_of_content({" << allow_delection_count << "})");
  end_document();
}

namespace xml {

void Element::print_on(std::ostream& os) const
{
  os << m_name;
}

} // namespace xml

} // namespace protocol
} // namespace evio
