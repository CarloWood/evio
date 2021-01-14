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
// large amounts of data with end_of_msg_finder_stream before returning
// a non-zero value. Even the whole document if that fits into memory.
//
// The default end_of_msg_finder_stream always returns 0. Therefore
// decode is only called once the full size of the document is received.
// This size must be provided through a callback function that is passed
// to set_next_decoder. If this is the last piece of data that needs to
// be decoded on this stream, you can use evio::protocol::EOFDecoder::instance()
// as next_decoder, which just closes the input device.
//
class DecoderStream : public std::istream, public Sink
{
 protected:
  std::function<int()> m_get_message_length;    // m_get_message_length() should return the total size of the input by the time end_of_msg_finder is called.
  int m_message_length;                         // Cached value of m_get_message_length().
  int m_total_len;                              // The total number of bytes that this decoder has received (by end_of_msg_finder).
  Sink* m_next_decoder;

 public:
  DecoderStream() : m_message_length(-1), m_total_len(0), m_next_decoder(nullptr) { }

  // See comment for end_of_msg_finder in evio::Decoder.
  size_t end_of_msg_finder(char const* new_data, size_t rlen, EndOfMsgFinderResult& result) final;

  // This is what end_of_msg_finder() returns (unless m_message_length was reached, then m_message_length is returned).
  virtual size_t end_of_msg_finder_stream(char const* new_data, size_t rlen);

  // Switch to next_decoder after having received exactly get_message_length() bytes.
  void set_next_decoder(Sink& next_decoder, std::function<int()> get_message_length)
  {
    m_next_decoder = &next_decoder;
    m_get_message_length = get_message_length;
  }

  friend class InputDevice;
  virtual void decode(int& allow_deletion_count, size_t msg_len) = 0;
};

} // namespace protocol
} // namespace evio

#endif // EVIO_PROTOCOL_DECODER_STREAM_H
