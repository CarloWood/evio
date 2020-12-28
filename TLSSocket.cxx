/**
 * evio -- A cwm4 git submodule for adding support for buffered, iostream oriented, epoll based I/O.
 *
 * @file
 * @brief Definition of class TLSSocket.
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

#include "sys.h"
#include "TLSSocket.h"
#include "EventLoopThread.h"
#include "utils/AIAlert.h"
#include "debug.h"
#include <iostream>
#include <iomanip>

namespace evio {

using protocol::TLS;

int TLSSocket::sync()
{
  DoutEntering(dc::evio, "TLSSocket::sync()");
  if (m_tls.is_post_handshake().is_true())
  {
    // Call base class implementation.
    return OutputDevice::sync();
  }
  // Since we skip calling sync() when is_post_handshake() returns WasFalse,
  // setting that bit requires testing if we have data in the output buffer.
  // As a result all data will be flushed once the handshake finished, even
  // if the user didn't request that explicitly.
  return 0;
}

void TLSSocket::write_to_fd(int& allow_deletion_count, int fd)
{
  DoutEntering(dc::evio, "TLSSocket::write_to_fd({" << allow_deletion_count << "}, " << fd << ") [" << this << ']');

  for (;;)
  {
    if (m_tls.is_post_handshake().is_true())
    {
      // The plain text must be encrypted and written using TLS::write.

      // The code below is largly a copy of OutputDevice::write_to_fd().
      OutputBuffer* const obuffer = m_obuffer;
      for (;;) // This runs over all allocated blocks, when we are done we 'return'.
      {
        size_t len; // Available number of characters in current block.
        if (!(len = obuffer->buf2dev_contiguous())
            && !(len = obuffer->buf2dev_contiguous_forced()))
        {
          Dout(dc::evio, "(Buffer now empty)");
          utils::FuzzyCondition nothing_to_get([obuffer]{
              return obuffer->StreamBufConsumer::nothing_to_get();
          });
          obuffer->restart_input_device_if_needed();
          if (AI_UNLIKELY(nothing_to_get.is_momentary_false()))
            continue;
          if (AI_UNLIKELY(!stop_output_device(allow_deletion_count, nothing_to_get)))
            continue;
          return;
        }

        // Do not send more than the maximum (negotiated) fragment length (this value is probably 16384, which is the maximum allowed by SLL specs).
        if (len > m_max_frag)
          len = m_max_frag;

        int err;
        ssize_t wlen = m_tls.write(obuffer->buf2dev_ptr(), len, err);   // EINTR is handled by TLS::write.
        if (AI_UNLIKELY(wlen == -1))
        {
          Dout(dc::notice, "TLS::write returned " << AIAlert::convert_to_error_code(err));
          if (err != EWOULDBLOCK)
          {
            // It can happen that the fd is already closed by another thread, as a result of a read event on this fd.
            if (err == EBADF && FileDescriptor::state_t::wat(m_state)->m_flags.is_dead())
            {
              Dout(dc::evio, "Leaving TLSSocket::write_to_fd() because fd was already closed.");
              return;
            }
            write_error(allow_deletion_count, err);
          }
          return;
        }
        obuffer->buf2dev_bump(wlen);
        obuffer->restart_input_device_if_needed();
        if ((size_t)wlen < len)
          return;			// We wrote as much as currently possible.
        break;
      }
    }
    else if (AI_UNLIKELY(!(m_connected_flags & is_connected)))
    {
      // As soon as we can write to a file descriptor, we are connected.
      m_connected_flags |= is_connected;
      m_tls.session_init(m_ServerNameIndication.c_str());
    }

    int error;          // Only valid when the s_handshake_error bit was set.
    int state = m_tls.do_handshake(error);

    // Do we need to stop the output device?
    if (TLS::is_blocked_or_handshake_finished(state) || !TLS::handshake_wants_write_and_not_blocked(state))
    {
#ifdef CWDEBUG
      // Call set_source() on an OutputDevice before starting it.
      if (!m_obuffer)
        DoutFatal(dc::core, "Error: m_obuffer == nullptr; call set_source() on an OutputDevice before starting it.");
#endif
      if (TLS::handshake_error(state))
      {
        if (m_connected)
          m_connected(allow_deletion_count, false);
        write_error(allow_deletion_count, error);
        break;
      }
      utils::FuzzyCondition condition_must_stop_output_device([this]{
          return m_tls.must_stop_output_device(m_obuffer);
      });
      bool go_to_top = false;
      if (condition_must_stop_output_device.is_momentary_false())
      {
        Dout(dc::tls, "Trying buffer again because condition_must_stop_output_device.is_momentary_false() returned true.");
        go_to_top = true;
      }
      // If during the cannonical test the buffer isn't empty anymore, continue writing.
      else if (AI_UNLIKELY(!stop_output_device(allow_deletion_count, condition_must_stop_output_device)))
      {
        Dout(dc::tls, "Trying buffer again because stop_output_device(allow_deletion_count, nothing_to_get) returned false.");
        go_to_top = true;
      }
      if (TLS::handshake_completed(state))
      {
        Dout(dc::tls, "Handshake completed!");
        m_max_frag = m_tls.get_max_frag();
        Dout(dc::tls, "m_max_frag = " << m_max_frag);
        ASSERT(handshake_completed());
        // Do the m_connected() callback at this point  (as opposed to when the TCP connection was established),
        // as in most cases it will be used as a "you can now send/receive data" signal...
        if (m_connected)
        {
          int count = allow_deletion_count;
          m_connected(allow_deletion_count, true);
          if (allow_deletion_count > count)
            // The device was marked for deletion.
            return;
        }
        if (go_to_top)  // Since we're post handshake, this can only be true when there is something in the output buffer.
          start_output_device();
      }
      if (go_to_top)
        continue;
      // Output device was stopped. Return.
      break;
    }
    // state == want_write; the handshake is not finished and wants to write.
    // Start output device in case it was stopped.
    start_output_device();
    break;
  }
}

void TLSSocket::read_from_fd(int& allow_deletion_count, int fd)
{
  DoutEntering(dc::evio, "TLSSocket::read_from_fd({" << allow_deletion_count << "}, " << fd << ") [" << this << ']');

  for (;;)
  {
    if (m_tls.is_post_handshake().is_true())
    {
      ssize_t space = m_ibuffer->dev2buf_contiguous();

      for (;;)
      {
        // Allocate more space in the buffer if needed.
        if (space == 0 &&
            (space = m_ibuffer->dev2buf_contiguous_forced()) == 0)
        {
          Dout(dc::warning, "InputDevice::read_from_fd(" << fd << "): the input buffer has reached max. capacity!");
          // See InputDevice::read_from_fd.
          if (m_ibuffer->has_multiple_blocks())
          {
            stop_input_device();
            return;
          }
          space = m_ibuffer->force_additional_block();
        }

        ssize_t rlen;
        char* new_data = m_ibuffer->dev2buf_ptr();

        int err;
        rlen = m_tls.read(new_data, space, err);          // EINTR is handled by TLS::recv.
        if (AI_UNLIKELY(rlen == -1))                      // A read error occured ?
        {
          Dout(dc::notice, "TLS::read returned " << AIAlert::convert_to_error_code(err));
          if (err != EWOULDBLOCK)
            read_error(allow_deletion_count, err);
          return;
        }

        if (rlen == 0)                      // EOF reached ?
        {
          Dout(dc::notice, "TLS::read returned 0 (EOF)");
          read_returned_zero(allow_deletion_count);
          return;
        }

        m_ibuffer->dev2buf_bump(rlen);

        // The data is now in the buffer. This is where we become the consumer thread.
        int prev_allow_deletion_count = allow_deletion_count;
        data_received(allow_deletion_count, new_data, rlen);

        if (AI_UNLIKELY(allow_deletion_count > prev_allow_deletion_count))
        {
          Dout(dc::evio, "Stopping with reading because data_received incremented allow_deletion_count.");
          break;    // We were closed.
        }

        // It might happen that more data is available, even if rlen < space (for example when the read()
        // was interrupted (POSIX allows to just return the number of bytes read so far)).
        // However, since this is unlikely, in this case we'll assume that the I/O space is exhausted
        // (see below).
        space -= rlen;

        // epoll(7) says: For stream-oriented files (e.g., pipe, FIFO, stream socket), the condition that
        // the read/write I/O space is exhausted can also be detected by checking the amount of data read
        // from / written to the target file descriptor. For example, if you call read(2) by asking to read
        // a certain amount of data and read(2) returns a lower number of bytes, you can be sure of having
        // exhausted the read I/O space for the file descriptor. The same is true when writing using write(2).
        //
        // Therefore for stream-oriented (and only for stream-oriented) devices it is safe to break here
        // when space > 0.
        if (space > 0)
          break;
      }

      return;
    }

    int error;          // Only valid when the s_handshake_error bit was set.
    int state = m_tls.do_handshake(error);

    // Do we need to stop the input device?
    if (TLS::is_blocked_or_handshake_finished(state))
    {
      // Did the handshake finish with an error?
      if (TLS::handshake_error(state))
      {
        if (m_connected)
          m_connected(allow_deletion_count, false);
        write_error(allow_deletion_count, error);
        break;
      }
      // Did the handshake finish successfully?
      if (TLS::handshake_completed(state))
      {
        Dout(dc::tls, "Handshake completed!");
        m_max_frag = m_tls.get_max_frag();
        Dout(dc::tls, "m_max_frag = " << m_max_frag);
        ASSERT(handshake_completed());
        m_connected_flags |= is_connected;
        // Do the m_connected() callback at this point  (as opposed to when the TCP connection was established),
        // as in most cases it will be used as a "you can now send/receive data" signal...
        if (m_connected)
        {
          int count = allow_deletion_count;
          m_connected(allow_deletion_count, true);
          if (allow_deletion_count > count)
            // Device is marked for deletion.
            return;
        }
        // It is impossible to test if the output buffer is empty from this thread.
        //
        // It would work to simply start the output device and let the write thread deal with it (that is,
        // the write thread would stop the output device again if the buffer turns out to be empty).
        // However, if there is a way to avoid a needless start and subsequent stop then that would be preferable.
        //
        // If we do some fuzzy test - and based on that start the output device, then
        // nothing is lost. The only thing that we want to avoid is that we end up with
        // a stopped output device while there is something in the output buffer.
        // It is not possible however that by doing nothing we end in that state unless
        // there is already something in the output buffer (that was flushed) and no
        // new flush happens after this point (from another thread).
        //
        // When something is, or was, written to the output buffer and flushed - then that
        // caused the output device to be started. So, it is necessary that subsequently
        // this was ignored from write_to_fd() because the TLS handshake had not finished
        // yet.
        //
        // Moreover, the output device begins started, so it must have been stopped in
        // the meantime (as part of the TLS handshake), which happens exclusively from
        // the write thread.
        //
        // Therefore, it is possible to know if there is something in the (plain text)
        // output buffer as detected by the write thread when it stopped the output
        // device.
        if (m_tls.need_start_output_device(state))
          start_output_device(state_t::wat(m_state));
        // It is very unlikely that there is more to read, immediately after the handshake.
        break;
      }

      // Stopping the input device could cause the application to exit if
      // this is the only device and the output device is stopped too.
      // Therefore, we will only stop the input device if
      // 1) the handshake is not finished,
      // 2) the handshake wants to read,
      // 3) the write thread is inside do_handshake.
      // See TLS::must_stop_input_device for the detailed argumentation.
      utils::FuzzyCondition condition_must_stop_input_device([this]{
          return m_tls.must_stop_input_device();
      });
      if (condition_must_stop_input_device.is_momentary_false())
      {
        Dout(dc::tls, "Trying buffer again because condition_must_stop_input_device.is_momentary_false() returned true (state = " << state << ").");
        continue;
      }
      // If during the cannonical test the buffer isn't empty anymore, continue writing. stop_input_device
      if (AI_UNLIKELY(!stop_input_device(state_t::wat(m_state), condition_must_stop_input_device)))
      {
        if (TLS::handshake_wants_write_and_blocked(state))
        {
          // This is a special case (state 01x1, see TLS::must_stop_input_device()).
          // We can't stop the input device because that might collide with the output
          // device being stopped too - marking the whole device as 'done'.
          // But simply returning might cause a tight loop because the fd still
          // has data available for reading.
          // If this message is printed a lot, then something needs to be done about it.
          Dout(dc::warning, "Read thread got blocked while write thread is active. Not able to stop input device.");
          return;
        }
        Dout(dc::tls, "Trying buffer again because stop_input_device(allow_deletion_count, nothing_to_get) returned false.");
        continue;
      }
      // Input device was stopped. Return.
      break;
    }
    // Not blocked and the handshake is not finished.
    if (TLS::handshake_wants_write_and_not_blocked(state))
      start_output_device();
    break;
  }
}

void TLSSocket::fd_init(int fd, bool make_non_blocking)
{
  DoutEntering(dc::evio, "TLSSocket::fd_init(" << fd << ", " << std::boolalpha << make_non_blocking << ") [" << this << "]");
  FileDescriptor::fd_init(fd, make_non_blocking);
  m_tls.set_device(this, fd, this, fd);     // We are both, input device and output device.
}

void TLSSocket::set_sni(std::string const& ServerNameIndication)
{
  // Call set_sni before you call tls_init. Do not call set_sni twice or after you called tls_init.
  ASSERT(m_ServerNameIndication.empty());
  // Do not pass an empty SNI to set_sni.
  ASSERT(!ServerNameIndication.empty());
  // Call set_sni before calling init.
  ASSERT(!get_flags().is_open());
  m_ServerNameIndication = ServerNameIndication;
}

void TLSSocket::tls_init(SocketAddress const& socket_address, std::string const& ServerNameIndication)
{
  if (!ServerNameIndication.empty())
    m_ServerNameIndication = ServerNameIndication;
  else
  {
    // Just pass a SIN.
    ASSERT(socket_address.is_ip());
    m_ServerNameIndication = socket_address.to_string(true);
  }
  m_max_frag = s_max_frag_magic;
}

} // namespace evio
