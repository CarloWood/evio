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

// Decoder passes contiguous chunks of data to decode.
//
// If a chunk (or message) crosses a memory allocation block boundary of the
// buffer, it is first copied to a new buffer. This is why the average size
// of the messages as returned by end_of_msg_finder should correspond to
// what the virtual average_message_length() (see base class) returns for this
// class (as that determines the size of the buffer).
//
// In general this means that you should pass something that is decodable,
// but not too large, to decode. Something between 64 and 512 bytes is perfect,
// while 10 kB would be a bit too much (have a look at DecoderStream if
// you need that).
//
// For example, if the processed protocol exists of decodable lines separated
// by newlines then those would be perfect. This is what is done by the
// default end_of_msg_finder.
//
class Decoder : public Sink
{
 public: // Should only be called by InputDevice::data_received or classes that override that.
  // Given the char array new_data of size rlen, returns the length of the string (starting at new_data) up to and
  // including the first newline char, if any. Otherwise returns 0.
  size_t end_of_msg_finder(char const* new_data, size_t rlen, EndOfMsgFinderResult& result) override;

  friend class InputDevice;
  // This should return true iff it called set_next_decoder.
  virtual void decode(int& allow_deletion_count, MsgBlock&& msg) = 0;
};

} // namespace protocol
} // namespace evio

#endif // EVIO_PROTOCOL_DECODER_H
