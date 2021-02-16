#include "sys.h"
#include "Encoder.h"
#include "Request.h"
#include "debug.h"

namespace evio::protocol::xmlrpc {

Encoder& operator<<(Encoder& encoder, Request const& request)
{
  // Write XML RPC header.
  encoder.m_output <<
    "<?xml version=\"1.0\"?>"
    "<methodCall>"
      "<methodName>" << request.method_name() << "</methodName>"
      "<params>";

  for(auto&& param : request)
    param->write_param(encoder.m_output);

  // Write XML RPC trailer.
  encoder.m_output <<
      "</params>"
    "</methodCall>";

  return encoder;
}

} // namespace evio::protocol::xmlrpc
