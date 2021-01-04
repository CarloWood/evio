#pragma once

#include "evio/Sink.h"

namespace evio {
namespace protocol {

class EOFDecoder : public Sink
{
 private:
  static EOFDecoder s_instance;

 public:
  static EOFDecoder& instance() { return s_instance; }

 protected:
  size_t end_of_msg_finder(char const* new_data, size_t rlen, EndOfMsgFinderResult& result) override
  {
    m_input_device->close_input_device();
    return 0;
  }
};

} // namespace protocol
} // namespace evio
