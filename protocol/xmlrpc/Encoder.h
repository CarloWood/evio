#pragma once

#include <iosfwd>

namespace evio::protocol::xmlrpc {

class Request;

class Encoder
{
 private:
  std::ostream& m_output;

 public:
  Encoder(std::ostream& output) : m_output(output) { }

  friend Encoder& operator<<(Encoder& encoder, Request const& request);
};

}// namespace evio::protocol::xmlrpc
