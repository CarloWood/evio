#pragma once

#include "evio/protocol/Decoder.h"
#include "utils/Dictionary.h"
#include <unordered_map>
#include <string_view>
#include <iosfwd>

namespace evio {
namespace protocol {

namespace xml {

class Element
{
 public:
  using index_type = int;

 private:
  index_type m_id;
  std::string m_name;

 public:
  Element(index_type id, std::string&& name) : m_id(id), m_name(std::move(name)) { }

  index_type id() const { return m_id; }
  std::string const& name() const { return m_name; }

  void print_on(std::ostream& os) const;

  friend std::ostream& operator<<(std::ostream& os, Element const& element)
  {
    element.print_on(os);
    return os;
  }
};

} // namespace xml

// This decoder deserializes XML.
//
// It only supports UTF-8.
//
class UTF8_SAX_Decoder : public Decoder
{
 public:
  using index_type = xml::Element::index_type;
  using enum_type = size_t;

 private:
  bool m_document_begin;
  utils::Dictionary<enum_type, std::vector<xml::Element>, index_type> m_dictionary;

 public:
  UTF8_SAX_Decoder() : m_document_begin(true) { }

 private:
  index_type get_element_id(std::string_view name);

 protected:
  void add(enum_type element_id, std::string&& element_name) { m_dictionary.add(element_id, element_name, xml::Element{static_cast<index_type>(element_id), std::move(element_name)}); }
  size_t end_of_msg_finder(char const* new_data, size_t rlen, evio::EndOfMsgFinderResult& result) final;
  void decode(int& allow_deletion_count, evio::MsgBlock&& msg) override;
  void end_of_content(int& allow_deletion_count) override;

  // And for enum_type, which implicitly converts to index_type anyway.
  xml::Element& element(index_type element_id) { return m_dictionary[element_id]; }
  xml::Element const& element(index_type element_id) const { return m_dictionary[element_id]; }

 protected:
  virtual void start_document(size_t content_length, std::string version, std::string encoding)
  {
    DoutEntering(dc::notice, "UTF8_SAX_Decoder::start_document(" << content_length << ", \"" << version << "\", \"" << encoding << "\")");
  }
  virtual void end_document() { DoutEntering(dc::notice, "UTF8_SAX_Decoder::end_document()"); }
  virtual void start_element(index_type element_id) { DoutEntering(dc::notice, "UTF8_SAX_Decoder::start_element({" << m_dictionary[element_id] << "})"); }
  virtual void end_element(index_type element_id) { DoutEntering(dc::notice, "UTF8_SAX_Decoder::end_element({" << m_dictionary[element_id] << "})"); }
  virtual void characters(std::string_view const& data) { DoutEntering(dc::notice, "UTF8_SAX_Decoder::characters(\"" << libcwd::buf2str(data.data(), data.size()) << "\")"); }
};

} // namespace protocol
} // namespace evio
