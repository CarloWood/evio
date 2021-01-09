// InputDevice.h must be included first.
#include "evio/InputDevice.h"

#ifndef EVIO_PROTOCOL_DECODER_STREAM_H
#define EVIO_PROTOCOL_DECODER_STREAM_H

#include "evio/Sink.h"
#include <cstring>
#include <istream>

namespace evio {

class InputDevice;

namespace protocol {

class DecoderStream : public std::istream, public Sink
{
 public:
  // See comment for end_of_msg_finder in evio::Decoder.
  size_t end_of_msg_finder(char const* new_data, size_t rlen, EndOfMsgFinderResult& result) override;

  friend class InputDevice;
  virtual void decode(int& allow_deletion_count) = 0;
};

} // namespace protocol
} // namespace evio

#endif // EVIO_PROTOCOL_DECODER_STREAM_H
