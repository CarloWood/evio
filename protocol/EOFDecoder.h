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
  EOFDecoder()
  {
    // Set content length to zero, which will cause end_of_content to be called.
    set_next_decoder(*this, [](){ return 0; });
  }

 protected:
  size_t end_of_msg_finder(char const* UNUSED_ARG(new_data), size_t CWDEBUG_ONLY(rlen), EndOfMsgFinderResult& UNUSED_ARG(result)) override
  {
    DoutEntering(dc::io, "EOFDecoder::end_of_msg_finder({" << rlen << "}) = 0");
    return 0;
  }

  void end_of_content(int& allow_deletion_count) override
  {
    DoutEntering(dc::io, "EOFDecoder::end_of_content({" << allow_deletion_count << "})");
    m_input_device->close_input_device(allow_deletion_count);
    // Keep an infinite chain of EOFDecoder going (ok not really, just to stop a crash).
    set_next_decoder(*this, [](){ return 0; });
  }
};

} // namespace protocol
} // namespace evio
