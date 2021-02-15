#include "evio/protocol/xmlrpc/write_value.h"
#include <iostream>

namespace xmlrpc {

constexpr int XMLRPC_CLASSNAME_CREATE(ClassName)::s_number_of_members;
constexpr std::array<char const*, XMLRPC_CLASSNAME_CREATE(ClassName)::s_number_of_members> XMLRPC_CLASSNAME_CREATE(ClassName)::s_xmlrpc_names;

void ClassName::write_param(std::ostream& output) const
{
  output << "<param>";
  write_value(output, *this);
  output << "</param>";
}

#ifdef CWDEBUG
void XMLRPC_CLASSNAME_CREATE(ClassName)::print_on(std::ostream& os) const
{
  char const* prefix = "";
  XMLRPC_FOREACH_MEMBER(ClassName, XMLRPC_WRITE_TO_OS)
}
#endif

} // namespace xmlrpc
