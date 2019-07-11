#include "sys.h"
#include "Interface.h"
#include <iostream>

namespace evio {

std::ostream& operator<<(std::ostream& os, Interface const& interface)
{
  os << "{name:\"" << interface.name() << "\", flags:" << interface.flags() << ", address:" << interface.address().to_string(true);
  if (interface.address().is_ip())
    os << ", netmask:" << interface.netmask();
  os << "}";
  return os;
}

} // namespace evio
