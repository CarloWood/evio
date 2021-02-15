#include "sys.h"
#include "RequestParam.h"
#include <iostream>
#include "debug.h"

namespace evio::protocol::xmlrpc {

void RequestParam::write_param(std::ostream& output) const
{
  output << "<param />";
}

} // namespace evio::protocol::xmlrpc
