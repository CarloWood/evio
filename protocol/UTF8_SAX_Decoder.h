#pragma once

#include "evio/protocol/Decoder.h"
#include "utils/Dictionary.h"
#include "utils/NodeMemoryPool.h"
#include <unordered_map>
#include <string_view>
#include <iosfwd>

namespace evio {
namespace protocol {

namespace xml {

class ElementType
{
 public:
  using index_type = int;

 private:
  index_type m_id;
#ifdef CWDEBUG
  std::string m_name;
#endif

 public:
  // This is a data_type of utils::Dictionary and therefore has mandatory arguments.
  ElementType(index_type id COMMA_CWDEBUG_ONLY(std::string name)) : m_id(id) COMMA_CWDEBUG_ONLY(m_name(std::move(name))) { }

  index_type id() const { return m_id; }

#ifdef CWDEBUG
  void print_on(std::ostream& os) const;

  friend std::ostream& operator<<(std::ostream& os, ElementType const& element)
  {
    element.print_on(os);
    return os;
  }
#endif
};

class ElementBase
{
 protected:
  ElementType::index_type m_id;
  ElementBase* m_parent;

 public:
  ElementBase(ElementType::index_type id, ElementBase* parent) : m_id(id), m_parent(parent) { }
  virtual ~ElementBase() { }
  // Objects derived from ElementBase must be allocated with:
  // utils::NodeMemoryPool pool(128, sizeof(LargestDerivedClass));
  // DerivedClass* foo = new(pool) DerivedClass(...constructor args...);        // Allocate memory from memory pool and construct object.
  // delete foo;
  void operator delete(void* ptr) { utils::NodeMemoryPool::static_free(ptr); }

  ElementType::index_type id() { return m_id; }
  ElementBase* parent() { return m_parent; }

  // FIXME: remove this debug stuff
  std::string tree()
  {
    std::stringstream ss;
    if (m_parent)
      ss << m_parent->tree();
    ss << " - " << name();
    return ss.str();
  }

  virtual std::string name() const = 0;
  virtual bool has_allowed_parent() = 0;
  virtual void characters(std::string_view const& data) = 0;
  virtual void end_element() = 0;
};

} // namespace xml

// This decoder deserializes XML.
//
// It only supports UTF-8.
//
class UTF8_SAX_Decoder : public Decoder
{
 public:
  using index_type = xml::ElementType::index_type;
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

  // And for enum_type, which implicitly converts to index_type anyway.
  //xml::ElementType& element(index_type element_id) { return m_dictionary[element_id]; }   // Commented out because this object is used for every element with the same name.
  xml::ElementType element_type(index_type element_id) const { return { element_id COMMA_CWDEBUG_ONLY(m_dictionary.word(element_id)) }; }

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
