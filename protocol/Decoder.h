// InputDevice.h must be included first.
#include "evio/InputDevice.h"

#ifndef EVIO_PROTOCOL_DECODER_H
#define EVIO_PROTOCOL_DECODER_H

#include "evio/Sink.h"
#include <cstring>

namespace evio {

class InputDevice;
class MsgBlock;

namespace protocol {

class Decoder : public Sink
{
 public: // Should only be called by InputDevice::data_received or classes that override that.
  // Given the char array new_data of size rlen, returns the length of the string (starting at new_data) up to and
  // including the first newline char, if any. Otherwise returns 0.
  size_t end_of_msg_finder(char const* new_data, size_t rlen, EndOfMsgFinderResult& result) override;

  friend class InputDevice;
  virtual void decode(int& allow_deletion_count, MsgBlock&& msg) = 0;
};

} // namespace protocol
} // namespace evio

#endif // EVIO_PROTOCOL_DECODER_H
