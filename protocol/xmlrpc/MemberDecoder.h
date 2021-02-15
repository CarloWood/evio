#pragma once

#include "DecoderBase.h"
#include "initialize.h"
#include "debug.h"

namespace evio::protocol::xmlrpc {

template<typename T>
class MemberDecoder : public DecoderBase<T>
{
  void got_characters(std::string_view const& data) override
  {
    // If the following results in the compile error: no matching function for call to 'initialize',
    // where T = YourType, then you need to overload xmlrpc::initialize(YourType&, std::string_view const& data).
    initialize(this->m_member, data);
  }

 public:
  using DecoderBase<T>::DecoderBase;
};

} // namespace evio::protocol::xmlrpc
