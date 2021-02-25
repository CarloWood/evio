/**
 * evio -- A cwm4 git submodule for adding support for buffered, iostream oriented, epoll based I/O.
 *
 * @file
 * @brief Definition of namespace evio; class InputDevice.
 *
 * @Copyright (C) 2018  Carlo Wood.
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
#include "InputDevice.h"
#include "StreamBuf.h"
#include "debug.h"
#ifdef CWDEBUG
#include <libcwd/buf2str.h>
#endif

namespace evio {

InputDevice::InputDevice() : m_sink(nullptr), m_ibuffer(nullptr), m_is_link_buffer(false)
{
  DoutEntering(dc::evio, "InputDevice::InputDevice() [" << this << ']');
}

InputDevice::~InputDevice()
{
  if (m_ibuffer)
  {
    // Delete the input buffer if it is no longer needed.
    m_ibuffer->release(this);
  }
}

#ifdef DEBUGDEVICESTATS
void InputDevice::init_input_device(state_t::wat const& state_w)
{
  RawInputDevice::init_input_device(state_w);
  m_received_bytes = 0;
}
#endif

void InputDevice::close_input_device(int& allow_deletion_count)
{
  bool need_call_to_closed = false;
  {
    state_t::wat state_w(m_state);
    if (AI_LIKELY(state_w->m_flags.is_r_open()))
    {
      // Only print debug output when this function actually does something.
      DoutEntering(dc::evio, "InputDevice::close_input_device({" << allow_deletion_count << "})"
#ifdef DEBUGDEVICESTATS
          " [received_bytes = " << m_received_bytes << "]"
#endif
          " [" << this << ']');
      need_call_to_closed = RawInputDevice::close_input_device(allow_deletion_count, state_w);
    }
    else
      // Bug in library: it should not be possible that this device is closed
      // and m_is_link_buffer is still set. The only reason for this test
      // is to make sure we didn't print no debug output but will still call
      // flush_output_device() below. If this assert ever fires, then print
      // the DoutEntering above also when m_is_link_buffer is set.
      ASSERT(!m_is_link_buffer);
  }
  if (m_is_link_buffer)
  {
    // Only do this one time.
    m_is_link_buffer = false;
    // Bug in library.
    ASSERT(dynamic_cast<LinkBufferPlus*>(static_cast<StreamBuf*>(m_ibuffer)) != nullptr);
    LinkBufferPlus* link_buffer = static_cast<LinkBufferPlus*>(static_cast<StreamBuf*>(m_ibuffer));
    link_buffer->flush_output_device();
  }
  if (need_call_to_closed)
    closed(allow_deletion_count);
}

void InputDevice::read_from_fd(int& allow_deletion_count, int fd)
{
  DoutEntering(dc::evio, "InputDevice::read_from_fd({" << allow_deletion_count << "}, " << fd << ") [" << this << ']');
#ifdef CWDEBUG
  // Call set_sink() on an InputDevice before starting it.
  if (!m_ibuffer)
    DoutFatal(dc::core, "Error: m_ibuffer == nullptr; call set_sink() on an InputDevice before starting it.");
#endif
  ssize_t space = m_ibuffer->dev2buf_contiguous();

  for (;;)
  {
    // Allocate more space in the buffer if needed.
    if (space == 0 &&
        (space = m_ibuffer->dev2buf_contiguous_forced()) == 0)
    {
      Dout(dc::warning, "InputDevice::read_from_fd(" << fd << "): the input buffer has reached max. capacity!");
      // Since below we become the consumer thread, aren't we now not already?
      // Aka, there is no other thread that is touching the buffer right now, no?
      if (m_ibuffer->has_multiple_blocks())
      {
        stop_input_device();      // Stop reading the filedescriptor.
        // After a call to stop_input_device() it is possible that another thread
        // starts it again and enters read_from_fd from the top. We are therefore
        // no longer allowed to do anything. We also don't need to do anything
        // anymore, but just saying. See README.devices for more info.
        return;
      }
      // See the comments in overflow_a StreamBufProducer::overflow_a.
      // In order to make sure we don't get into a deadlock where nothing
      // is read from the buffer because it is undecodable and nothing is
      // written either because dev2buf_contiguous_forced returns 0 we have
      // to convince the latter to allocate memory, regardless of the
      // current setting.
      space = m_ibuffer->force_additional_block();
    }

    // At this point space == epptr() - pptr() > 0.

    ssize_t rlen;
    char* new_data = m_ibuffer->dev2buf_ptr();          // pptr().

    for (;;)                                            // Loop for EINTR.
    {
      rlen = ::read(fd, new_data, space);
      if (AI_LIKELY(rlen != -1))                        // A read error occured ?
        break;
      int err = errno;
      Dout(dc::system|dc::evio|dc::warning|error_cf, "read(" << fd << ", " << (void*)new_data << ", " << space << ") = -1");
      if (err == EINTR)
        continue;
      if (err != EAGAIN && err != EWOULDBLOCK)
        read_error(allow_deletion_count, err);
      return;
    }

    if (rlen == 0)                      // EOF reached ?
    {
      Dout(dc::system|dc::evio, "read(" << fd << ", " << (void*)new_data << ", " << space << ") = 0 (EOF)");
      try
      {
        read_returned_zero(allow_deletion_count);
        // In the case of a PersistentInputFile, read_returned_zero calls stop_input_device() and returns.
        // Therefore we must also return immediately from read_returned_zero, see above.
        return;
      }
      catch (OneMoreByte const& persistent_input_file_exception)      // This can only happen for a PersistentInputFile.
      {
        Dout(dc::evio, "Stopping device failed: there was still more to read!");
        *new_data = persistent_input_file_exception.byte;
        rlen = 1;
      }
    }

    m_ibuffer->dev2buf_bump(rlen);
    Dout(dc::system|dc::evio, "read(" << fd << ", " << (void*)new_data << ", " << space << ") = " << rlen);
#ifdef DEBUGDEVICESTATS
    m_received_bytes += rlen;
#endif
    Dout(dc::evio, "Read " << rlen << " bytes from fd " << fd <<
#ifdef DEBUGDEVICESTATS
    " [total received now: " << m_received_bytes << " bytes]"
#endif
      " [" << this << ']');

    // The data is now in the buffer. This is where we become the consumer thread.
    int prev_allow_deletion_count = allow_deletion_count;
    data_received(allow_deletion_count, new_data, rlen);

    if (AI_UNLIKELY(allow_deletion_count > prev_allow_deletion_count))
    {
      Dout(dc::evio, "Stopping with reading because data_received incremented allow_deletion_count.");
      break;    // We were closed.
    }

    // It might happen that more data is available, even if rlen < space (for example when the read() was
    // interrupted (POSIX allows to just return the number of bytes read so far)).
    // If this is a File (including PersistenInputFile) then we really should not take any risk and
    // continue to read till the EOF, and end this function with a call to stop_input_device().
    // If this is a socket then it still won't hurt to continue to read till -say- read returns EAGAIN.
    // So lets just do that.
    space -= rlen;

    // epoll(7) says: For stream-oriented files (e.g., pipe, FIFO, stream socket), the condition that
    // the read/write I/O space is exhausted can also be detected by checking the amount of data read
    // from / written to the target file descriptor. For example, if you call read(2) by asking to read
    // a certain amount of data and read(2) returns a lower number of bytes, you can be sure of having
    // exhausted the read I/O space for the file descriptor. The same is true when writing using write(2).
    //
    // Therefore for stream-oriented (and only for stream-oriented) devices it would be safe to
    // break here when space > 0.
    //
    // If the fd that we're handling here is message oriented, then the program is ill-formed, because
    // it is possible that we're at the end of the buffer and read -say- just a single byte, which would
    // be much less than the typical message length of a message oriented protocol. But this function
    // is also used for regular files, so we have to test this explicitly.
    if (space > 0 && is_stream_oriented())
      break;
  }
}

void InputDevice::data_received(int& allow_deletion_count, char const* new_data, size_t rlen)
{
  DoutEntering(dc::io, "InputDevice::data_received({" << allow_deletion_count << "}, \"" << buf2str(new_data, rlen) << "\", " << rlen << ") [" << this << ']');

  // This function is both the Get Thread and the Put Thread; meaning that no other
  // thread should be accessing this buffer by either reading from it or writing to
  // it while we're here, or the program is ill-formed.

  bool single_block_left = false;
  size_t len;
  EndOfMsgFinderResult end_of_message_finder_result;

  // Cache m_content_length, if provided.
  m_sink->initialize_content_length();

  // The code below assumes this.
  ASSERT(rlen > 0);

  // Split all rlen bytes into messages and decode those.
  for (;;)
  {
    // Use this variable to detect a change of decoder.
    Sink* current_decoder = m_sink;

    // Do not pass more data to the current decoder than current_decoder.m_content_length.
    size_t decoder_rlen = current_decoder->decoder_rlen(rlen);
    len = current_decoder->end_of_msg_finder(new_data, decoder_rlen, end_of_message_finder_result);
    if (len == 0)
    {
      // Cumulate undecodable bytes.
      m_msg_len += decoder_rlen;
      return;
    }

    // We seem to have a complete new message and need to call `decode'.

    // Calculate the size of the decodable chunk.
    size_t msg_len = m_msg_len + len;
    m_msg_len = 0;

    // Call the right decode.
    if (end_of_message_finder_result.m_sink_type == decoder_stream_sink)
    {
      // The decoder is a DecoderStream.
      protocol::DecoderStream* decoder = static_cast<protocol::DecoderStream*>(current_decoder);
      Dout(dc::notice, "before: total_read = " << m_ibuffer->total_read() << "; gptr = " << (void*)m_ibuffer->raw_gptr());
      decoder->decode(allow_deletion_count, msg_len);
      Dout(dc::notice, "after:  total_read = " << m_ibuffer->total_read() << "; gptr = " << (void*)m_ibuffer->raw_gptr());
      // This is what should be left in the buffer. From that we can deduce what has been read
      // using the std::istream interface.
      m_ibuffer->update_total_read(rlen - len);
    }
    else
    {
      // The decoder is a Decoder.
      protocol::Decoder* decoder = static_cast<protocol::Decoder*>(current_decoder);

      if (single_block_left ||    // Once we have only a single block left, that will continue to be the case.
          (single_block_left = !m_ibuffer->has_multiple_blocks()))
      {
        char* start = m_ibuffer->raw_gptr();
        // This has worked before... so just a sanity check. If it fails there is a bug in the library.
        ASSERT(msg_len == (size_t)(new_data - start) + len);
        decoder->decode(allow_deletion_count, MsgBlock(start, msg_len, m_ibuffer->get_get_area_block_node()));
        m_ibuffer->raw_gbump(msg_len);
      }
      else
      {
        // This has worked before... so just a sanity check. If it fails there is a bug in the library.
        //
        // The new message must start at gptr(), the beginning of the unread data in the buffer,
        // so the total length of the new message is the total size of the data in the buffer
        // minus any extra data that was already read beyond this message.
        ASSERT(msg_len == m_ibuffer->get_data_size() - (rlen - len));

        if (m_ibuffer->is_contiguous(msg_len))
        {
          decoder->decode(allow_deletion_count, MsgBlock(m_ibuffer->raw_gptr(), msg_len, m_ibuffer->get_get_area_block_node()));
          m_ibuffer->raw_gbump(msg_len);
        }
        else
        {
          size_t block_size = m_ibuffer->m_minimum_block_size;
          if (AI_UNLIKELY(msg_len > block_size))
            block_size = utils::malloc_size(msg_len + sizeof(MemoryBlock)) - sizeof(MemoryBlock);
          MemoryBlock* memory_block = MemoryBlock::create(block_size);
          AllocTag((void*)memory_block, "read_from_fd: memory block to make message contiguous");
          m_ibuffer->raw_sgetn(memory_block->block_start(), msg_len);
          decoder->decode(allow_deletion_count, MsgBlock(memory_block->block_start(), msg_len, memory_block));
          memory_block->release();
        }
      }
    }

    // After processing this message, the remaining data in the buffer must be equal
    // to the number of bytes that we read beyond that message.
    ASSERT(m_ibuffer->get_data_size() == rlen - len);

    // Keep track of the total number of bytes received by this decoder.
    current_decoder->m_total_len += msg_len;
    // We should never pass more than m_content_length to the current decoder!
    ASSERT(current_decoder->m_total_len <= current_decoder->m_content_length);

    m_ibuffer->raw_reduce_buffer_if_empty();
    rlen -= len;
    new_data += len;

    for (;;)
    {
      // Handle a decoder switch.
      if (current_decoder->m_total_len == current_decoder->m_content_length)
      {
        Dout(dc::notice, "Content length reached.");
        // Notify the decoder.
        current_decoder->end_of_content(allow_deletion_count);
        // The next line (also) sets m_sink to current_decoder->m_next_decoder.
        current_decoder->switch_protocol_decoder(*current_decoder->m_next_decoder);               // FIXME: pass a buffer_full_watermark and max_alloc.
      }

      if (!FileDescriptor::state_t::wat(m_state)->m_flags.is_readable())
        return;

      if (m_sink != current_decoder)                      // Did the call to decode switch protocol?
      {
        current_decoder = m_sink;                         // Really switch decoder.
        current_decoder->initialize_content_length();     // Initialize the cached message length.
        continue;                                         // Go to top in order to make EOFDecoder work.
      }
      else if (rlen == 0)
        return;   // Buffer is precisely empty anyway.

      // Not really a loop.
      break;
    }

    end_of_message_finder_result.reset();
  }
}

size_t LinkBufferPlus::end_of_msg_finder(char const* UNUSED_ARG(new_data), size_t UNUSED_ARG(rlen), EndOfMsgFinderResult& UNUSED_ARG(result))
{
  DoutEntering(dc::io, "LinkBufferPlus::end_of_msg_finder");
  // We're just hijacking InputDevice::data_received here. We're both, get and put thread.
  start_output_device();
  // This function MUST return 0 (returning a value larger than 0 is only allowed
  // by Decoder::end_of_msg_finder() or classes derived from Decoder).
  // See the cast to Decoder in InputDevice::data_received.
  return 0;
}

} // namespace evio
