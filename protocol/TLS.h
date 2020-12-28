/**
 * evio -- A cwm4 git submodule for adding support for buffered, iostream oriented, epoll based I/O.
 *
 * @file
 * @brief Declarations of classes TLSSource, TLSSink and TLS.
 *
 * @Copyright (C) 2019  Carlo Wood.
 *
 * RSA-1024 0x624ACAD5 1997-01-26                    Sign & Encrypt
 * Fingerprint16 = 32 EC A7 B6 AC DB 65 A6  F6 F6 55 DD 1C DC FF 61
 *
 * This file is part of evio.
 *
 * Evio is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Evio is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with evio.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include "evio/FileDescriptor.h"
#include "evio/Source.h"
#include "evio/Sink.h"
#include "evio/SocketAddress.h"
#include "debug.h"
#include <mutex>
#include <vector>
#include <string_view>
#ifdef CWDEBUG
#include <libcwd/buf2str.h>
#endif

#if defined(CWDEBUG) && !defined(DOXYGEN)
NAMESPACE_DEBUG_CHANNELS_START
extern channel_ct tls;
NAMESPACE_DEBUG_CHANNELS_END
#endif

namespace evio {

namespace protocol {

struct TLSSource : public Source
{
 protected:
  OutputBuffer* create_buffer(OutputDevice* output_device, size_t buffer_full_watermark, size_t max_alloc) override
  {
    DoutEntering(dc::evio, "TLSSource::create_buffer(" << output_device << ", " << buffer_full_watermark << ", " << max_alloc << ")");
    m_output_device = output_device;
    OutputBuffer* output_buffer = new OutputBuffer(output_device, minimum_block_size(), buffer_full_watermark, max_alloc);
    return output_buffer;
  }
};

struct TLSSink : public InputDecoder
{
  size_t end_of_msg_finder(const char*, size_t) override
  {
    DoutEntering(dc::evio, "TLSSink::end_of_msg_finder()");
    return 0;
  }

  void decode(int& CWDEBUG_ONLY(allow_deletion_count), MsgBlock&& CWDEBUG_ONLY(msg)) override
  {
    DoutEntering(dc::evio, "TLSSink::decode({" << allow_deletion_count << ", {MsgBlock:" << libcwd::buf2str(msg.get_start(), msg.get_size()) << "})");
  }
};

class TLS
{
 private:
  // SSL session state bits.
  static constexpr int s_inside_do_handshake = 1;       // Must be 1.
  static constexpr int s_want_write = 4;                // Must be 4 (2 is used).
  static constexpr int s_post_handshake = 8;
  static constexpr int s_have_plain_text = 16;          // Set by the write thread when it stops the output device because
                                                        // the handshake doesn't need to write, but there is something in
                                                        // the output buffer.
  static constexpr int s_handshake_completed = 32;      // Not used for m_session_state.
  static constexpr int s_handshake_error = 64;          // Not used for m_session_state.

 public:
  static bool handshake_wants_write_and_not_blocked(int session_state) { return (session_state & (s_inside_do_handshake|s_want_write|s_post_handshake)) == s_want_write; }
  static bool handshake_wants_read_and_not_blocked(int session_state) { return (session_state & (s_inside_do_handshake|s_want_write|s_post_handshake)) == 0; }
  static bool handshake_wants_write_and_blocked(int session_state) { return (session_state & (s_inside_do_handshake|s_want_write|s_post_handshake)) == (s_inside_do_handshake|s_want_write); }
  static bool handshake_wants_read_and_blocked(int session_state) { return (session_state & (s_inside_do_handshake|s_want_write|s_post_handshake)) == s_inside_do_handshake; }
  static bool is_blocked_or_handshake_finished(int session_state) { return (session_state & (s_inside_do_handshake|s_post_handshake|s_handshake_error)) != 0; }
  static bool is_inside_do_handshake(int session_state) { return (session_state & s_inside_do_handshake); }
  static bool is_post_handshake(int session_state) { return (session_state & s_post_handshake); }
  static bool handshake_completed(int session_state) { return (session_state & s_handshake_completed); }
  static bool handshake_error(int session_state) { return (session_state & s_handshake_error); }
  static bool need_start_output_device(int session_state) { return (session_state & s_have_plain_text); }

  static std::string_view session_state_to_str(int session_state);

 public:
  class Cleanup;

 private:
  static std::once_flag s_flag;                                 // Used for calling global_tls_initialization().
  static std::vector<std::string> get_CA_files();               // Returns a trusted CA certificate bundle (used by global_tls_initialization()).
  static void global_tls_initialization();
  static void global_tls_deinitialization() noexcept;
  static std::string session_error_string(int session_error);   // Return a descriptive string for session_error.

  std::atomic<int> m_session_state;
  boost::intrusive_ptr<InputDevice> m_input_device;             // The underlaying input device.
  boost::intrusive_ptr<OutputDevice> m_output_device;           // The underlaying output device.
  void* m_read_session;                                         // Handle to the underlaying SSL struct used for reading.
  void* m_write_session;                                        // Handle to the underlaying SSL struct used for writing.
  int m_recv_fd;                                                // Copy of m_input_device->get_fd().
  int m_send_fd;                                                // Copy of m_output_device->get_fd().
  int m_recv_error;                                             // Set to errno when send(2) returns an error.
  int m_send_error;                                             // Set to errno when recv(2) returns an error.
  uint32_t m_max_frag;
#ifdef DEBUGDEVICESTATS
  size_t& m_sent_bytes;
  size_t& m_received_bytes;
#endif

 public:
#ifdef DEBUGDEVICESTATS
  TLS(size_t& sent_bytes, size_t& received_bytes);
#else
  TLS();
#endif
  ~TLS();

  void set_device(InputDevice* input_device, int recv_fd, OutputDevice* output_device, int send_fd);
  void session_init(std::string const& ServerNameIndication);
  int do_handshake(int& error);
  int read(char* plain_text, ssize_t len, int& error);
  int write(char const* plain_text, size_t len, int& error);

  // Bits of TLS::m_session_state
  //  _ post_handshake
  // / _ want_write
  // |/  _ inside_do_handshake
  // || /
  // || |   Required action   Possible transitions to  Condition result
  // || |
  // 00x0    stop              00x0, 00x1, 01x0, 10x0   WasTrue
  // 00x1    stop              00x0, 01x0, 10x0         WasTrue
  // 01x0    do not stop       01x0                     False
  // 01x1    stop              00x0, 01x0, 10x0         WasTrue
  // 10x0    stop if           10x0                     obuffer->StreamBufConsumer::nothing_to_get() (False or WasTrue)
  // 10x1   not possible
  // 11x0   not possbile
  // 11x1   not possible
  //
  // If the post_handshake bit is not set, then it was never set before.
  // Therefore, since in the immediate past is_blocked_or_handshake_finished()
  // returned true, the inside_do_handshake bit must have been set.
  // Hence, if we see that neither post_handshake nor inside_do_handshake
  // are set then the read thread returned from do_handshake and
  // signalled if it wants to continue with reading or writing by clearing
  // or setting the want_write bit; however, since we also get here when
  // state == 0, it is possible that in that case it was THIS thread that
  // just reset the inside_do_handshake bit (after having just executed
  // do_handshake). In that case the read thread is still running and
  // could cause transitions from 00x0 to any other state, but that doesn't
  // change the fact that the required action to stop is a WasTrue.
  //
  // Hence, if we see that handshake_wants_write_and_not_blocked(state)
  // then the read thread must have left do_handshake (resetting
  // inside_do_handshake) and set the want_write bit. That means the
  // handshake is not finished yet and the handshake wants to continue
  // with writing (not reading!).
  // Therefore the *read* thread will not re-enter do_handshake and
  // thus m_session_state can't change anymore.
  //
  // Therefore this condition must return fuzzy::WasTrue for all states
  // except where handshake_wants_write(state), in which case it should
  // return fuzzy::False.
  //
  // If is_post_handshake(state) then instead it should return
  // obuffer->StreamBufConsumer::nothing_to_get(). Note that a state of
  // post_handshake can also no longer change, leaving the fuzzy::False
  // returned by StreamBufConsumer::nothing_to_get() at fuzzy::False.
  utils::FuzzyBool must_stop_output_device(OutputBuffer const* obuffer)
  {
    int state = m_session_state.load(std::memory_order_relaxed);
    if (handshake_wants_write_and_not_blocked(state))
      return fuzzy::False;
    utils::FuzzyBool output_buffer_is_empty = obuffer->StreamBufConsumer::nothing_to_get();
    if (output_buffer_is_empty.is_false())
      m_session_state.fetch_or(s_have_plain_text, std::memory_order_release);
    if (is_post_handshake(state))
      return output_buffer_is_empty;
    return fuzzy::WasTrue;
  }

  // Bits of TLS::m_session_state
  //  _ post_handshake
  // / _ want_write
  // |/  _ inside_do_handshake
  // || /
  // || |   Required action   Possible transitions to  Condition result
  // || |
  // 00x0    do not stop       00x0                     False
  // 00x1    stop              00x0, 01x0, 10x0         WasTrue
  // 01x0    do not stop       00x0, 01x0, 01x1, 10x0   False
  // 01x1    do not stop       00x0, 01x0, 10x0         False
  // 10x0    do not stop       10x0                     False
  // 10x1   not possible
  // 11x0   not possbile
  // 11x1   not possible
  //
  // We can not stop the input device when the state is 01x0 because
  // that means that the write thread is running which might stop
  // the output device (and stopping both input and output device
  // could terminate the application; or more specifically it means
  // that 'we are done' with this device in evio terms - which is
  // obviously not true).
  //
  // Because that state (01x0) can transition to 01x1 (when the
  // write thread enters do_handshake()), that state can not cause
  // us to stop the input device either or the result of state 01x0
  // would need WasFalse to be returned - which is not allowed (or
  // rather, that can't work: due to a race condition we could
  // *miss* stopping on state 01x1).
  //
  // Obviously we do not want to stop the input device when the
  // state is 00x0 or 10x0; in the first case because the handshake
  // is not finished and it wants to read, and in the second because
  // the handshake is finished and we can return to the sane strategy
  // of never stopping to read an input device until we're done with it.
  //
  // We HAVE to stop when the state is 00x1 because reading is
  // required but the write thread is handling the handshake at
  // the moment (so we can't). Not stopping could lead to an immediate
  // return to read_from_fd and thus cause a tight loop using 100% cpu.
  //
  // None of the other states can transition to 00x1, so that we
  // can return fuzzy::False for all of them as is required (see above).
  //
  // The reason that a transition to 00x1 is not possible is because
  // 1) when the write thread is inside do_handshake (xxx1) the only
  //    possible transition is when the write thread leaves do_handshake
  //    which always resets the least significant bit (xxx1 --> xxx0).
  // 2) Once the state is 10x0 the handshake is finished and the state
  //    won't return to an unfinished handshake.
  // 3) If the write thread is outside do_handshake and the state is
  //    01x0 then the only possible (first) transition is to 01x1 (
  //    which subsequently could change back to 01x1, to 10x0 or to
  //    00x0, and)
  // 4) If the write thread is outside do_handshake and the state is
  //    00x0 then the write thread is stopped, so it won't make any
  //    additional changes anymore.
  //
  // Not stopping in the state 01x1 is unfortunate, but discussed
  // elsewhere.
  utils::FuzzyBool must_stop_input_device() const
  {
    int state = m_session_state.load(std::memory_order_relaxed);
    return handshake_wants_read_and_blocked(state) ? fuzzy::WasTrue : fuzzy::False;
  }

  // Accessor for the post_handshake state bit.
  // Once the post_handshake bit is set, it will not be reset.
  utils::FuzzyBool is_post_handshake() const
  {
    // std::memory_order_acquire to synchronize with m_max_frag.
    return is_post_handshake(m_session_state.load(std::memory_order_acquire)) ? fuzzy::True : fuzzy::WasFalse;
  }

  // Return the maximum (negotiated) fragment length.
  uint32_t get_max_frag() const { return m_max_frag; }

  // These should always be inline: they are swallowed by static functions in TLS.cxx,
  // which is why they have to be public. Do not call them from anywhere else.
  [[gnu::always_inline]] inline int recv(char* buf, int sz);
  [[gnu::always_inline]] inline int send(char* buf, int sz);
};

enum error_codes
{
};

std::error_code make_error_code(error_codes);

} // namespace protocol
} // namespace evio

// Register evio::error_codes as valid error code.
namespace std {

template<> struct is_error_code_enum<evio::protocol::error_codes> : true_type { };

} // namespace std
