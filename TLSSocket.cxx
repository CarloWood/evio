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
#ifdef CWDEBUG
#include <libcwd/buf2str.h>
#endif

namespace evio {

using protocol::TLS;

//static
char const* TLSSocket::session_state_to_str(TLSSocket::session_state_type session_state)
{
  switch (session_state)
  {
    AI_CASE_RETURN(preconnect);
    AI_CASE_RETURN(handshake_want_write);
    AI_CASE_RETURN(handshake_want_read);
    AI_CASE_RETURN(app_want_write);
    AI_CASE_RETURN(app_idle_out);
    AI_CASE_RETURN(app_write_error);
  }
  return "UNKNOWN session_state_type";
}

std::ostream& operator<<(std::ostream& os, TLSSocket::session_state_type session_state)
{
  return os << TLSSocket::session_state_to_str(session_state);
}

int TLSSocket::sync()
{
  DoutEntering(dc::evio, "TLSSocket::sync()");
  session_state_type session_state = m_session_state.load(std::memory_order_relaxed);
  Dout(dc::tls, "m_session_state == " << session_state);
  if (session_state >= app_want_write)
  {
    // Call base class implementation.
    return OutputDevice::sync();
  }
  return 0;
}

#ifdef CWDEBUG
static std::string buf2hex(char* buf, size_t len)
{
  std::ostringstream out;
  constexpr int nb = 6;
  bool const small = len <= 2 * nb;
  int mn = small ? len : nb;
  out << std::hex << std::setfill('0') << std::setw(2);
  char const* separator = "0x";
  for (int n = 0; n < mn; ++n)
  {
    out << separator << (int)(unsigned char)buf[n];
    separator = " 0x";
  }
  if (!small)
  {
    out << " ...";
    for (size_t n = len - nb; n < len; ++n)
    {
      out << separator << (int)(unsigned char)buf[n];
      separator = " 0x";
    }
  }
  return out.str();
}
#endif

void TLSSocket::write_to_fd(int& allow_deletion_count, int fd)
{
  DoutEntering(dc::evio, "TLSSocket::write_to_fd({" << allow_deletion_count << "}, " << fd << ") [" << this << ']');
  // Sync with the written value of m_max_frag.
  session_state_type session_state = m_session_state.load(std::memory_order_acquire);
  Dout(dc::evio, "m_session_state == " << session_state);

  // We keep this lock from writing to the peer till we were able to update m_session_state
  // for the unlikely case that the peer would reply faster than that ;).
  std::unique_lock<std::mutex> session_state_lock(m_session_state_mutex, std::defer_lock);

  do
  {
    if (session_state == app_want_write)
    {
#if 0
      // The encrypted data must be written to an internal MatrixSSL out data buffer.
      // The matrixssl API steps for this method are as follows:
      //
      // 1. The user passes the plaintext and length to matrixSslEncodeToOutdata.
      // 2. The application calls matrixSslGetOutdata to retrieve the encoded data and length to be sent (SSL always adds some overhead to the message size).
      // 3. The application sends the out data buffer contents to the peer.
      // 4. The application calls matrixSslSentData with the # of bytes that were actually sent.

#ifdef CWDEBUG
      // Call set_source() on an OutputDevice before starting it.
      if (!m_obuffer)
        DoutFatal(dc::core, "Error: m_obuffer == nullptr; call set_source() on an OutputDevice before starting it.");
#endif
      OutputBuffer* const obuffer = m_obuffer;
      for (;;) // Allow to continue in the extremely small chance that the buffer is filled with new data after detecting that it was empty.
      {
        size_t len; // Available number of characters in current block.
        if (!(len = obuffer->buf2dev_contiguous())
            && !(len = obuffer->buf2dev_contiguous_forced()))
        {
          Dout(dc::evio, "(Buffer now empty)");
          // Note: A call to `m_obuffer->reduce_buffer_if_empty' is not necessary because
          // `buf2dev_contiguous_forced' calls `force_next_contiguous_number_of_bytes'
          // which only returns 0 when `underflow_a' returned EOF in which case that already
          // reduced the buffer if necessary.
          //
          // However, even though the buffer was JUST empty - it is possible that right
          // here another thread that wrote new data to the buffer calls sync(), which
          // would be ignored because we didn't reset the ACTIVE bit yet. Although unlikely
          // it could cause a call to sync() to be lost. And if no new data is written,
          // then this data would never be flushed out.
          //
          // Therefore, call stop_output_device with a condition that re-checks if the
          // buffer is really empty inside the critical area of m_state.
          utils::FuzzyCondition nothing_to_get([obuffer]{
              return obuffer->StreamBufConsumer::nothing_to_get();
          });
          obuffer->restart_input_device_if_needed();
          // When buf2dev_contiguous_forced() returned zero then the buffer is empty.
          // So, it is unlikely that a microsecond later it isn't anymore but we're
          // not allowed to call stop_output_device with a false condition (simply
          // because it makes no sense).
          if (AI_UNLIKELY(nothing_to_get.is_momentary_false()))
          {
            Dout(dc::tls, "Trying buffer again because nothing_to_get.is_momentary_false() returned true.");
            continue;
          }
          // If during the cannonical test the buffer isn't empty anymore, continue reading.
          if (AI_UNLIKELY(!stop_output_device(allow_deletion_count, nothing_to_get)))
          {
            Dout(dc::tls, "Trying buffer again because stop_output_device(allow_deletion_count, nothing_to_get) returned false.");
            continue;
          }
          m_session_state.store(session_state, std::memory_order_relaxed);
          Dout(dc::tls, "Set m_session_state to session_state (" << session_state << ").");
          return;
        }

        // Do not send more than the maximum (negotiated) frag length (this value is probably 16384, which is the maximum allow by SLL specs).
        if (len > m_max_frag)
          len = m_max_frag;

        // session_state == app_want_write.
        int32_t encoded_len = m_tls.matrixSslEncodeToOutdata(obuffer->buf2dev_ptr(), len);
        if (AI_UNLIKELY(encoded_len < 0))
        {
          write_error(allow_deletion_count, -encoded_len);
          if (session_state < app_want_write)                   // Handshake not completed means m_connected() wasn't called yet.
          {
            if (m_connected)
              m_connected(allow_deletion_count, false);
          }
          m_session_state = write_error_out;
          Dout(dc::evio, "m_session_state = write_error_out");
          return;
        }
        session_state = OutData_ready;
        Dout(dc::evio, "session_state = " << session_state);
        obuffer->buf2dev_bump(len);
        break;
      }
#endif
    }
    else if (AI_UNLIKELY(!(m_connected_flags & is_connected)))
    {
      // As soon as we can write to a file descriptor, we are connected.
      m_connected_flags |= is_connected;
      m_tls.session_init(m_ServerNameIndication.c_str());
      m_tls.set_fd(m_fd);
      session_state = handshake_want_write;
      Dout(dc::evio, "session_state = " << session_state);
    }

    for (;;)
    {
      //char* buf;
      ASSERT(session_state == handshake_want_write || session_state == app_want_write);

      if (session_state == handshake_want_write)
      {
        auto res = m_tls.do_handshake();
        if (res == TLS::HANDSHAKE_COMPLETE)
        {
          // Handshake finished.
          utils::FuzzyCondition condition_empty([this]{
                return m_obuffer->StreamBufProducer::nothing_to_get();
              });
          // Stop the output device if the buffer is empty.
          if (condition_empty.is_momentary_true())
          {
            stop_output_device(allow_deletion_count, condition_empty);
            session_state = app_idle_out;
            break;
          }
          else
            session_state = app_want_write;
          Dout(dc::evio, "session_state == " << session_state);
        }
        else if (res == TLS::HANDSHAKE_WANT_WRITE)
        {
          // Couldn't write everything that we wanted to write.
          break;
        }
        else if (res == TLS::HANDSHAKE_WANT_READ)
        {
          // Nothing to write anymore.
          stop_output_device(allow_deletion_count);
          session_state = handshake_want_read;
          Dout(dc::evio, "session_state == " << session_state);
          break;
        }
        else
        {
          assert(false); // To be implemented.
        }
      }

#if 0
      int32_t len = m_tls.matrixSslGetOutdata(&buf);      // This function can be called safely multiple times, therefore session_state is not changed after calling it.

      if (len == 0)     // Success. No pending data remaining.
      {
        session_state = session_state == handshake_want_write ? handshake_want_read : app_idle_out;
        m_session_state.store(session_state, std::memory_order_relaxed);
        Dout(dc::evio, "All data was written --> m_session_state = " << session_state);
        stop_output_device(allow_deletion_count);
        return;
      }

#if EWOULDBLOCK != EAGAIN
      int nr_eagain_errors = 1;
#endif
      ssize_t wlen;
      // Take the lock just before writing.
      session_state_lock.lock();
      for (;;)    // EINTR / EAGAIN loop.
      {
        Dout(dc::system|continued_cf, "write(" << fd << ", {" << buf2hex(buf, len) << "}, " << len << ") = ");
        wlen = ::write(fd, buf, len);
        Dout(dc::finish|cond_error_cf(wlen == -1), wlen << " [" << this << ']');
        if (AI_LIKELY(wlen != -1))
          break;

        int err = errno;
        // It can happen that the fd is already closed by another thread, as a result of a read event on this fd.
        if (err == EBADF && FileDescriptor::state_t::wat(m_state)->m_flags.is_dead())
        {
          Dout(dc::evio, "Leaving TLSSocket::write_to_fd() because fd was already closed.");
          m_session_state = preconnect_out;
          Dout(dc::evio, "m_session_state = preconnect_out");
          return;
        }
        if (err == EINTR)
          continue;             // Try to write the same data again.
        if (err == EWOULDBLOCK)
        {
          m_session_state.store(session_state, std::memory_order_relaxed);
          Dout(dc::tls, "Set m_session_state to session_state (" << session_state << ").");
          return;
        }
#if EWOULDBLOCK != EAGAIN
        if (err == EAGAIN)
        {
          if (nr_eagain_errors--)
            continue;           // Try to write the same data again.
          m_session_state.store(session_state, std::memory_order_relaxed);
          Dout(dc::tls, "Set m_session_state to session_state (" << session_state << ").");
          return;
        }
#endif
        session_state_lock.unlock();
        write_error(allow_deletion_count, err);
        if (session_state < app_want_write)                     // Handshake not completed means m_connected() wasn't called yet.
        {
          if (m_connected)
            m_connected(allow_deletion_count, false);
        }
        m_session_state = write_error_out;
        Dout(dc::evio, "m_session_state = write_error_out");
        return;
      }

#ifdef DEBUGDEVICESTATS
      m_sent_bytes += wlen;
#endif
#ifdef CWDEBUG
      Dout(dc::evio|continued_cf, "Wrote " << wlen << " bytes to fd " << fd
#ifdef DEBUGDEVICESTATS
          << " [total sent now " << m_sent_bytes << " bytes]"
#endif
      );
      if (AI_UNLIKELY(wlen < len))
        Dout(dc::continued, " (Tried to write " << len << " bytes)");
      Dout(dc::finish, " [" << this << ']');
#endif

      // session_state == handshake_want_write || session_state == OutData_ready (after calling matrixSslGetOutdata and writing successfully some data to the peer).
      TLS::data_result_type res = m_tls.matrixSslSentData(wlen);

      if (AI_UNLIKELY(res == TLS::REQUEST_CLOSE))
      {
        session_state_lock.unlock();
        Dout(dc::evio, "Closing device because matrixSslSentData() returned MATRIXSSL_REQUEST_CLOSE.");
        close(allow_deletion_count);
        if (session_state < app_want_write)                     // Handshake not completed means m_connected() wasn't called yet.
        {
          if (m_connected)
            m_connected(allow_deletion_count, false);
        }
        m_session_state = preconnect_out;
        Dout(dc::evio, "m_session_state = preconnect_out");
        return;                   // All done.
      }

      if (res == TLS::SUCCESS)
      {
        session_state = session_state == handshake_want_write ? handshake_want_read : app_want_write;
        if (session_state == handshake_want_read)
        {
          m_session_state.store(session_state, std::memory_order_relaxed);
          Dout(dc::tls, "No pending data remaining --> m_session_state = " << session_state);
          stop_output_device(allow_deletion_count);
          // Note that during a handshake session_state_lock has been locked from before
          // writing the last (successful) message to the peer until after that we updated
          // m_session_state and stopped the output device.
          return;	                // Success. No pending data remaining. This unlocks session_state_lock.
        }
        Dout(dc::tls, "No pending data remaining --> session_state = " << session_state);
        session_state_lock.unlock();
        // Go to beginning of function to test if there is more to write.
        break;
      }

      session_state_lock.unlock();

      if (res == TLS::HANDSHAKE_COMPLETE)
      {
        Dout(dc::notice, "Handshake complete...");
        m_max_frag = m_tls.get_max_frag();
        // We could already check if there is output data available here, and if so, encode it,
        // but checking if the buffer is empty is rather involved and the fd is very likely
        // writable anyway at this moment-- so just call write_to_fd and use the check at the top.
        session_state = app_want_write;
        // Release to sync m_max_frag.
        m_session_state.store(app_want_write, std::memory_order_release);
        Dout(dc::evio, "m_session_state = app_want_write; m_max_frag = " << m_max_frag);
        m_connected_flags |= is_connected;
        if (m_connected)
          m_connected(allow_deletion_count, true);
        break;
      }

      ASSERT(res == TLS::REQUEST_SEND);
      // There is more to send.
#endif
    }
  }
  while (session_state == app_want_write);
  m_session_state.store(session_state, std::memory_order_relaxed);
  Dout(dc::tls, "Set m_session_state to session_state (" << session_state << ").");
}

void TLSSocket::read_from_fd(int& allow_deletion_count, int fd)
{
  DoutEntering(dc::evio, "TLSSocket::read_from_fd({" << allow_deletion_count << "}, " << fd << ") [" << this << ']');
  session_state_type session_state = m_session_state.load(std::memory_order_acquire);
  Dout(dc::tls, "m_session_state == " << session_state);

  if (session_state == handshake_want_read)
  {
    auto res = m_tls.do_handshake();
    if (res == TLS::HANDSHAKE_COMPLETE)
    {
      // Handshake finished.
      utils::FuzzyCondition condition_not_empty([this]{
            return !m_obuffer->StreamBufConsumer::nothing_to_get();
          });
      // Start the output device if the buffer is non-empty.
      if (condition_not_empty.is_momentary_true())
      {
        start_output_device(state_t::wat(m_state), condition_not_empty);
        session_state = app_want_write;
      }
      else
        session_state = app_idle_out;
      Dout(dc::evio, "session_state == " << session_state);
    }
    else if (res == TLS::HANDSHAKE_WANT_WRITE)
    {
      // Read everything we wanted to read. Now we want to write again.
      start_output_device();
      session_state = handshake_want_write;
      Dout(dc::evio, "session_state == " << session_state);
    }
    else if (res != TLS::HANDSHAKE_WANT_READ)
    {
      assert(false); // To be implemented.
    }
  }
  else
  {
    Dout(dc::warning, "Unhandled state");
    stop_input_device();
  }

#if 0
  for (;;)
  {
    char* encoded_data;
    int32_t space = m_tls.matrixSslGetReadbuf(&encoded_data);

    if (space == 0)
    {
      DoutFatal(dc::core, "No space to write?! I don't think this should ever happen or matrixssl is broken.");
      stop_input_device();      // Stop reading the filedescriptor.
      break;
    }

    ssize_t rlen;
    for (;;)                                    // Loop for EINTR.
    {
      rlen = ::read(fd, encoded_data, space);
      if (AI_LIKELY(rlen != -1))                // A read error occured ?
        break;
      int err = errno;
      Dout(dc::system|dc::evio|dc::warning|error_cf, "read(" << fd << ", " << (void*)encoded_data << ", " << space << ") = -1");
      if (err == EINTR)
        continue;
      if (err != EAGAIN && err != EWOULDBLOCK)
        read_error(allow_deletion_count, err);
      return;
    }

    if (rlen == 0)                              // EOF reached ?
    {
      Dout(dc::system|dc::evio, "read(" << fd << ", " << (void*)encoded_data << ", " << space << ") = 0 (EOF)");
      read_returned_zero(allow_deletion_count);
      return;
    }

    Dout(dc::system|dc::evio, "read(" << fd << ", \"" << buf2hex(encoded_data, rlen) << "\", " << space << ") = " << rlen);
#ifdef DEBUGDEVICESTATS
    m_received_bytes += rlen;
#endif
    Dout(dc::evio, "Read " << rlen << " bytes from fd " << fd <<
#ifdef DEBUGDEVICESTATS
    " [total received now: " << m_received_bytes << " bytes]"
#endif
      " [" << this << ']');

    char const* decoded_data;
    uint32_t decoded_data_len;
    TLS::data_result_type res = m_tls.matrixSslReceivedData(rlen, &decoded_data, &decoded_data_len);

    for (;;)
    {
      if (res == TLS::REQUEST_SEND)
      {
        // Success. The processing of the received data resulted in an SSL response
        // message that needs to be sent to the peer. If this return code is hit we
        // should call matrixSslGetOutdata to retrieve the encoded outgoing data.
        {
          std::unique_lock<std::mutex> lk(m_session_state_mutex);
          // This reply means that the last thing we sent to the server was a completed message,
          // this response is a reply to, which must have resulted in the thread that called
          // write_to_fd to process a TLS::SUCCESS from matrixSslSentData and thus stopped the
          // output device. Aka, no other thread will be reading or writing m_session_state at
          // this point and it is safe for us to change it.
          m_session_state.store(handshake_want_write, std::memory_order_relaxed);
        }
        Dout(dc::evio, "m_session_state = handshake_want_write");
        start_output_device();    // TLSSocket::write_to_fd calls TLS::matrixSslGetOutdata.
        // There is currently nothing more to read from the server, but no reason to stop monitoring the fd for input.
        return;
      }

      if (res == TLS::REQUEST_RECV)
      {
        // Success. More data must be received and matrixSslReceivedData must be called again.
        // We must first call matrixSslGetReadbuf again to receive the updated buffer pointer
        // and length to where the remaining data should be read into.
        break;                    // To top of loop.
      }

      if (res == TLS::SUCCESS)
      {
        // We can get here when matrixSslProcessedData (at the end of the for loop) returned SUCCESS.
        // This indicates that there are no additional records in the data buffer that require processing.
        break;
      }

      if (res == TLS::HANDSHAKE_COMPLETE ||
          AI_UNLIKELY(!handshake_completed() && (res == TLS::APP_DATA || res == TLS::APP_DATA_COMPRESSED)))
      {
        // Success. The SSL handshake is complete. This return code is returned to client side
        // implementation during a full handshake after parsing the FINISHED message from the server.
        // It is possible for a server to receive this value if a resumed handshake is being
        // performed where the client sends the final FINISHED message.
        Dout(dc::notice, "Handshake complete!");
        // Get negotiated max. fragment size.
        m_max_frag = m_tls.get_max_frag();
        // Since we just made a connection with a server, we probably have something in the output buffer
        // ready to be written, so just start the output device. Also, the call to m_connected() might
        // start the output device, so the state should be set correctly here.
        {
          std::unique_lock<std::mutex> lk(m_session_state_mutex);
          // This reply means that the last thing we sent to the server was a completed FINISHED message,
          // see the comment above for TLS::REQUEST_SEND.
          m_session_state.store(app_want_write, std::memory_order_release);
        }
        Dout(dc::evio, "m_session_state = app_want_write; m_max_frag = " << m_max_frag);
        // Do the m_connected() callback at this point  (as opposed to when the TCP connection was established),
        // as in most cases it will be used as a "you can now send/receive data" signal...
        m_connected_flags |= is_connected;
        if (m_connected)
          m_connected(allow_deletion_count, true);
        start_output_device();
        // It is possible to receive APP_DATA without receiving HANDSHAKE_COMPLETE.
        // This implies that the handshake completed.
        if (res == TLS::HANDSHAKE_COMPLETE)
          return;
      }

      if (res == TLS::RECEIVED_ALERT_WARNING || res == TLS::RECEIVED_ALERT_FATAL)
      {
        // Success. The data that was processed was an SSL alert message. In this case,
        // the decoded_data pointer will be two bytes (decoded_data_len will be 2) in which the
        // first byte will be the alert level and the second byte will be the alert
        // description. After examining the alert, the user must call matrixSslProcessedData
        // to indicate the alert was processed and the data may be internally discarded
#ifdef CWDEBUG
        int alert_description = decoded_data[1];
#endif
        if (res == TLS::RECEIVED_ALERT_FATAL)
        {
          Dout(dc::warning, "Received fatal SSL alert message with description: " << alert_description);
          res = m_tls.matrixSslProcessedData(&decoded_data, &decoded_data_len);
          Dout(dc::notice, "After receiving a SSL_ALERT_LEVEL_FATAL matrixSslProcessedData returned " << res);
          ASSERT(res != TLS::RECEIVED_ALERT_FATAL && res != TLS::RECEIVED_ALERT_WARNING && res != TLS::APP_DATA && res != TLS::APP_DATA_COMPRESSED);
          close();
          return;
        }
        Dout(dc::warning, "Received warning SSL alert message with description: " << alert_description);
      }
      else if (res == TLS::APP_DATA)
      {
        // Success. The data that was processed was application data that the user
        // should process. In this return code case the ptbuf and ptLen output
        // parameters will be valid. The user may process the data directly from
        // ptbuf or copy it aside for later processing. After handling the data the
        // user must call matrixSslProcessedData to indicate the plain text
        // data may be internally discarded
        Dout(dc::tls, "Got application data.");

        // This is where we become the consumer thread.
        int prev_allow_deletion_count = allow_deletion_count;
        data_received(allow_deletion_count, decoded_data, decoded_data_len);

        if (AI_UNLIKELY(allow_deletion_count > prev_allow_deletion_count))
        {
          Dout(dc::evio, "Stopping with reading because data_received incremented allow_deletion_count.");
          m_tls.matrixSslProcessedData(&decoded_data, &decoded_data_len);
          return;    // We were closed.
        }
      }
      else if (res == TLS::APP_DATA_COMPRESSED)
      {
        // Success. The application data that is returned needs to be inflated with
        // zlib before being processed. This return code is only possible if the
        // USE_ZLIB_COMPRESSION define has been enabled and the peer has
        // agreed to compression. Compression is not advised due to TLS attacks.
        DoutFatal(dc::core, "Got compressed application data.");
      }

      res = m_tls.matrixSslProcessedData(&decoded_data, &decoded_data_len);
    }

    // This being a TCP socket, it is safe to assume that we're done reading it when
    // we read less than what we tried to read (and even so, epoll would/will just
    // generate a new EPOLLIN event).
    if (rlen < space)
      break;
  }
#endif
}

void TLSSocket::data_received(int& allow_deletion_count, char const* new_data, size_t rlen)
{
  DoutEntering(dc::io, "TLSSocket::data_received({" << allow_deletion_count << "}, \"" << buf2str(new_data, rlen) << "\", " << rlen << ") [" << this << ']');

#if 0
  // This function is both the Get Thread and the Put Thread; meaning that no other
  // thread should be accessing this buffer by either reading from it or writing to
  // it while we're here, or the program is ill-formed.

  size_t len;
  while ((len = m_sink->end_of_msg_finder(new_data, rlen)) > 0)
  {
    // If end_of_msg_finder returns a value larger than 0 then m_sink must be (derived from) a InputDecoder.
    InputDecoder* input_decoder = static_cast<InputDecoder*>(m_sink);

    if (AI_LIKELY(m_ibuffer->buffer_empty()))
    {
      input_decoder->decode(allow_deletion_count, MsgBlock(new_data, len));
    }
    else
    {
      // There is still unprocessed data in m_ibuffer. Append more data to it to make it one complete message.
      if (m_ibuffer->sputn(new_data, len) == EOF)
        goto buffer_full1;

      // The new message must start at the beginning of the buffer,
      // so the total length of the new message is total size of the buffer.
      size_t msg_len = m_ibuffer->get_data_size();

      if (m_ibuffer->has_multiple_blocks())
      {
        // There is only one message in the buffer and that starts at the beginning,
        // so if it has multiple blocks the message spans more than one block.
        ASSERT(!m_ibuffer->is_contiguous(msg_len));
        size_t block_size = utils::malloc_size(msg_len + sizeof(MemoryBlock)) - sizeof(MemoryBlock);
        MemoryBlock* memory_block = MemoryBlock::create(block_size);
        AllocTag((void*)memory_block, "TLSSocket::data_received: memory block to make message contiguous");
        m_ibuffer->raw_sgetn(memory_block->block_start(), msg_len);
        input_decoder->decode(allow_deletion_count, MsgBlock(memory_block->block_start(), msg_len, memory_block));
        memory_block->release();
      }
      else
      {
        input_decoder->decode(allow_deletion_count, MsgBlock(m_ibuffer->raw_gptr(), msg_len, m_ibuffer->get_get_area_block_node()));
        m_ibuffer->raw_gbump(msg_len);
      }

      ASSERT(m_ibuffer->get_data_size() == 0);
      m_ibuffer->raw_reduce_buffer_if_empty();
      if (!FileDescriptor::state_t::wat(m_state)->m_flags.is_readable())
        return;
    }

    rlen -= len;
    if (rlen == 0)
      return; // Buffer is precisely empty anyway.
    new_data += len;
  }

  // Append remaining data to m_ibuffer, if any.
  // The cast is OK because we are both consumer and producer.
  if (m_ibuffer->sputn(new_data, rlen) != EOF)
    return;
  // sputn returned EOF.

buffer_full1:
  // Buffer full?!
  // This is pretty unlikely, because that means that the buffer is full with
  // received data that can't be decoded... Aka it will never happen unless
  // someone has been feeding us undecodable data - just close the connection.
  Dout(dc::warning, "TLSSocket input buffer full?! Closing connection...");
  close(allow_deletion_count);
#endif
}

void TLSSocket::fd_init(int fd, bool make_non_blocking)
{
  DoutEntering(dc::evio, "TLSSocket::fd_init(" << fd << ", " << std::boolalpha << make_non_blocking << ") [" << this << "]");
  FileDescriptor::fd_init(fd, make_non_blocking);
  m_tls.set_device(this, fd, this, fd);     // We are both, input device and output device.
}

void TLSSocket::set_sni(std::string const& ServerNameIndication)
{
  // Do not call set_sni (before or) after you already called tls_init (or do not call set_sni twice).
//  ASSERT(m_ServerNameIndication.empty());
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
  m_tls.set_device(this, this);
  std::atomic_init(&m_session_state, preconnect);
  m_max_frag = s_max_frag_magic;
}

} // namespace evio
