#pragma once

#include <string>
#include <iosfwd>

namespace evio::protocol::xmlrpc {

class RequestParam
{
 public:
  virtual ~RequestParam() = default;

  virtual char const* method_name() const = 0;

  virtual void write_param(std::ostream& output) const;
};

} // namespace evio::protocol::xmlrpc
