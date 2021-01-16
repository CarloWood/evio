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

// The DecoderStream provides access to an istream to read directly from
// the buffer. It does, therefore, not guarantee contiguousness, but rather
// leaves the data in the buffer whereever it is. Since this avoids any
// copy of data (to make it contiguous) it is perfectly fine to accumulate
// large amounts of data with end_of_msg_finder before returning a non-zero
// value. Even the whole document if that fits into memory.
//
// The default end_of_msg_finder always returns 0. Therefore decode is only
// called once the full size of the document is received. This size must be
// provided through a callback function that is passed to set_next_decoder.
// If this is the last piece of data that needs to be decoded on this stream,
// you can use evio::protocol::EOFDecoder::instance() as next_decoder,
// which just closes the input device.
//
class DecoderStream : public std::istream, public Sink
{
 public:
  // See comment for end_of_msg_finder in evio::Decoder.
  size_t end_of_msg_finder(char const* UNUSED_ARG(new_data), size_t UNUSED_ARG(rlen), EndOfMsgFinderResult& UNUSED_ARG(result)) override
  {
    // Just wait till we have the whole document.
    return 0;
  }

  virtual void decode(int& allow_deletion_count, size_t msg_len) = 0;
};

} // namespace protocol
} // namespace evio

#endif // EVIO_PROTOCOL_DECODER_STREAM_H
