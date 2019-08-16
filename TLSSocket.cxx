#include "sys.h"
#include "TLSSocket.h"
#include "utils/AIAlert.h"
#include "debug.h"
#include <libcwd/buf2str.h>

namespace evio {

using protocol::TLS;

void TLSSocket::write_to_fd(int& allow_deletion_count, int fd)
{
  DoutEntering(dc::evio, "TLSSocket::write_to_fd({" << allow_deletion_count << "}, " << fd << ") [" << this << ']');

  if (AI_UNLIKELY(!(m_connected_flags & is_connected)))
  {
    // As soon as we can write to a file descriptor, we are connected.
    m_connected_flags |= is_connected;
    if ((m_connected_flags & signal_connected))
      m_tls.session_init(m_remote_address);             // Generate the CLIENT HELLO message.
  }

  for (;;)
  {
    char* buf;
    int32_t len = m_tls.matrixSslGetOutdata(&buf);

    if (len == 0)     // Success. No pending data remaining.
    {
      Dout(dc::evio, "All data was written.");
      stop_output_device(allow_deletion_count);
      return;
    }

#if EWOULDBLOCK != EAGAIN
    int nr_eagain_errors = 1;
#endif
try_again_write1:
    Dout(dc::system|continued_cf, "write(" << fd << ", \"" << buf2str(buf, len) << "\", " << len << ") = ");
    ssize_t wlen = ::write(fd, buf, len);
    Dout(dc::finish|cond_error_cf(wlen == -1), wlen << " [" << this << ']');

    if (AI_UNLIKELY(wlen == -1))
    {
      int err = errno;
      // It can happen that the fd is already closed by another thread, as a result of a read event on this fd.
      if (err == EBADF && FileDescriptor::state_t::wat(m_state)->m_flags.is_dead())
      {
        Dout(dc::evio, "Leaving TLSSocket::write_to_fd() because fd was already closed.");
        return;
      }
      if (err == EINTR)
        goto try_again_write1;
      if (err == EWOULDBLOCK)
        return;
#if EWOULDBLOCK != EAGAIN
      if (err == EAGAIN)
      {
        if (nr_eagain_errors--)
          goto try_again_write1;
        return;
      }
#endif
      write_error(allow_deletion_count, err);
      return;
    }

#ifdef DEBUGDEVICESTATS
    m_sent_bytes += wlen;
#endif
    Dout(dc::evio|continued_cf, "Wrote " << wlen << " bytes to fd " << fd
#ifdef DEBUGDEVICESTATS
      << " [total sent now " << m_sent_bytes << " bytes]"
#endif
      );
    if (AI_UNLIKELY(wlen < len))
      Dout(dc::continued, " (Tried to write " << len << " bytes)");
    Dout(dc::finish, " [" << this << ']');

    TLS::data_result_type res = m_tls.matrixSslSentData(wlen);

    if (AI_UNLIKELY(res == TLS::REQUEST_CLOSE))
    {
      Dout(dc::evio, "Closing device because matrixSslSentData() returned MATRIXSSL_REQUEST_CLOSE.");
      close(allow_deletion_count);
      return;                   // All done.
    }

    if (res == TLS::SUCCESS)
    {
      stop_output_device(allow_deletion_count);
      return;	                // Success. No pending data remaining.
    }

    if (res == TLS::HANDSHAKE_COMPLETE)
    {
      Dout(dc::notice, "Handshake complete...");
      return;                   // All done.
    }

    // There is more to send.
  }
}

void TLSSocket::read_from_fd(int& allow_deletion_count, int fd)
{
  DoutEntering(dc::evio, "TLSSocket::read_from_fd({" << allow_deletion_count << "}, " << fd << ") [" << this << ']');

  for (;;)
  {
    char* new_data;
    int32_t space = m_tls.matrixSslGetReadbuf(&new_data);

    if (space == 0)
    {
      DoutFatal(dc::core, "No space to write?! I don't think this should ever happen or matrixssl is broken.");
      stop_input_device();      // Stop reading the filedescriptor.
      return;
    }

    ssize_t rlen;
    for (;;)                                            // Loop for EINTR.
    {
      rlen = ::read(fd, new_data, space);
      if (AI_UNLIKELY(rlen == -1))                      // A read error occured ?
      {
        int err = errno;
        Dout(dc::system|dc::evio|dc::warning|error_cf, "read(" << fd << ", " << (void*)new_data << ", " << space << ") = -1");
        if (err != EINTR)
        {
          if (err != EAGAIN && err != EWOULDBLOCK)
            read_error(allow_deletion_count, err);
          return;
        }
      }
      break;
    }

    if (rlen == 0)                      // EOF reached ?
    {
      Dout(dc::system|dc::evio, "read(" << fd << ", " << (void*)new_data << ", " << space << ") = 0 (EOF)");
      read_returned_zero(allow_deletion_count);
      return;
    }

    Dout(dc::system|dc::evio, "read(" << fd << ", \"" << buf2str(new_data, rlen) << "\", " << space << ") = " << rlen);
#ifdef DEBUGDEVICESTATS
    m_received_bytes += rlen;
#endif
    Dout(dc::evio, "Read " << rlen << " bytes from fd " << fd <<
#ifdef DEBUGDEVICESTATS
    " [total received now: " << m_received_bytes << " bytes]"
#endif
      " [" << this << ']');

    char* alert_buf;
    uint32_t alert_buf_len;
    TLS::data_result_type res = m_tls.matrixSslReceivedData(rlen, &alert_buf, &alert_buf_len);

    for (;;)
    {
      if (res == TLS::REQUEST_SEND)
      {
        // Success. The processing of the received data resulted in an SSL response
        // message that needs to be sent to the peer. If this return code is hit we
        // should call matrixSslGetOutdata to retrieve the encoded outgoing data.
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

      if (res == TLS::HANDSHAKE_COMPLETE)
      {
        // Success. The SSL handshake is complete. This return code is returned to client side
        // implementation during a full handshake after parsing the FINISHED message from the server.
        // It is possible for a server to receive this value if a resumed handshake is being
        // performed where the client sends the final FINISHED message.
        Dout(dc::notice, "Handshake complete!");
        return;
      }

      if (res == TLS::RECEIVED_ALERT_WARNING || res == TLS::RECEIVED_ALERT_FATAL)
      {
        // Success. The data that was processed was an SSL alert message. In this case,
        // the alert_buf pointer will be two bytes (alert_buf_len will be 2) in which the
        // first byte will be the alert level and the second byte will be the alert
        // description. After examining the alert, the user must call matrixSslProcessedData
        // to indicate the alert was processed and the data may be internally discarded
        int alert_description = alert_buf[1];
        if (res == TLS::RECEIVED_ALERT_FATAL)
        {
          Dout(dc::warning, "Received fatal SSL alert message with description: " << alert_description);
          res = m_tls.matrixSslProcessedData(&alert_buf, &alert_buf_len);
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
        DoutFatal(dc::core, "Got application data.");
      }
      else if (res == TLS::APP_DATA_COMPRESSED)
      {
        // Success. The application data that is returned needs to be inflated with
        // zlib before being processed. This return code is only possible if the
        // USE_ZLIB_COMPRESSION define has been enabled and the peer has
        // agreed to compression. Compression is not advised due to TLS attacks.
        DoutFatal(dc::core, "Got compressed application data.");
      }
      res = m_tls.matrixSslProcessedData(&alert_buf, &alert_buf_len);
    }
  }
}

} // namespace evio
