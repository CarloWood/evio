#pragma once

#include "evio/protocol/Decoder.h"
#include "utils/Dictionary.h"
#include <unordered_map>
#include <string_view>
#include <iosfwd>

namespace evio {
namespace protocol {

// This decoder deserializes XML.
//
// It only supports UTF-8.
//
class UTF8_SAX_Decoder : public Decoder
{
 public:
  using index_type = int;
  using enum_type = size_t;

 private:
  bool m_document_begin;
  utils::Dictionary<enum_type, index_type> m_dictionary;

 public:
  UTF8_SAX_Decoder() : m_document_begin(true) { }

 private:
  index_type get_element_id(std::string_view name);

 protected:
  void add(enum_type element_id, std::string&& element_name)
  {
    m_dictionary.add(element_id, element_name);
  }
  size_t end_of_msg_finder(char const* new_data, size_t rlen, evio::EndOfMsgFinderResult& result) final;
  void decode(int& allow_deletion_count, evio::MsgBlock&& msg) override;
  void end_of_content(int& allow_deletion_count) override;

#ifdef CWDEBUG
  // And for enum_type, which implicitly converts to index_type anyway.
  std::string const& name_of(index_type element_id) const { return m_dictionary.word(element_id); }
#endif

 protected:
  virtual void start_document(size_t content_length, std::string version, std::string encoding)
  {
    DoutEntering(dc::notice, "UTF8_SAX_Decoder::start_document(" << content_length << ", \"" << version << "\", \"" << encoding << "\")");
  }
  virtual void end_document() { DoutEntering(dc::notice, "UTF8_SAX_Decoder::end_document()"); }
  virtual void start_element(index_type element_id) { DoutEntering(dc::notice, "UTF8_SAX_Decoder::start_element({" << m_dictionary.word(element_id) << "})"); }
  virtual void end_element(index_type element_id) { DoutEntering(dc::notice, "UTF8_SAX_Decoder::end_element({" << m_dictionary.word(element_id) << "})"); }
  virtual void characters(std::string_view const& data) { DoutEntering(dc::notice, "UTF8_SAX_Decoder::characters(\"" << libcwd::buf2str(data.data(), data.size()) << "\")"); }
};

} // namespace protocol
} // namespace evio
