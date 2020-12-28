#pragma once

#include "evio/StreamBuf.h"
#include "utils/log2.h"
#include <iosfwd>

namespace evio {
namespace protocol {

// Base class of Sink base class of Decoder, which in turn should
// be the base class of protocol decoder implementations.

class MessageLengthInterface
{
 public:
  virtual ~MessageLengthInterface() { }

  // This really should be defined in the derived MessageLengthInterface class; however, a size of 512 isn't so large that it would
  // be a disadvantage and in most cases is will be actually larger than the real average message length, so using this as default
  // should be possible in many cases.
  //
  // The actual meaning of this is to increase the chance that after receiving a message it will be contiguous in the input buffer.
  // For this the minimum block size of the receive buffer will be set to sixteen times this value. The kernel socket buffer (which is
  // twice the SO_RCVBUF set with setsockopt) will be set to rcvbuf_size() which is by default also equal to the minimum block size.
  virtual size_t average_message_length() const { return 512; }

  virtual size_t minimum_block_size_estimate() const { return 16 * average_message_length(); }

  // This should be treated as a requested_minimum_block_size because the user can override it.
  virtual size_t minimum_block_size() const
  {
    // This rounds off minimum_block_size_estimate() to a power of two minus evio::block_overhead_c.
    // The power of two picked is such that the returned value is at least 0.8 * minimum_block_size_estimate().
    return (1 << (3 + utils::log2((minimum_block_size_estimate() + 5 * evio::block_overhead_c / 4 - 1) / 5))) - evio::block_overhead_c;
  }

  friend std::ostream& operator<<(std::ostream& os, MessageLengthInterface const& message_length_interface);
};

} // namespace protocol
} // namespace evio
