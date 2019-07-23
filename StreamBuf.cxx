// evio -- Event Driven I/O support.
//
//! @file
//! @brief Definition of namespace evio; class StreamBuf.
//
// Copyright (C) 2004, 2018 Carlo Wood.
//
// RSA-1024 0x624ACAD5 1997-01-26                    Sign & Encrypt
// Fingerprint16 = 32 EC A7 B6 AC DB 65 A6  F6 F6 55 DD 1C DC FF 61
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// Configure with --enable-debug-buffers, which should define DEBUGDBSTREAMBUF,
// (and define CWDEBUG) to get an ENORMOUS amount of debug output.

#include "sys.h"
#include "debug.h"
#include "StreamBuf.h"
#include "InputDevice.h"
#include "OutputDevice.h"
#include "utils/is_power_of_two.h"
#include <cstdlib>
#ifdef CWDEBUG
#include <libcwd/buf2str.h>
#include <libcwd/char2str.h>
using namespace libcwd;
#else
// Comment this out if you want to be able to use --disable-debug and --enable-debug-buffers at the same time.
#undef DEBUGDBSTREAMBUF
#ifdef DEBUGDBSTREAMBUF
#define buf2str std::string
#endif
#endif
#ifdef DEBUGSTREAMBUFSTATS
#include <map>
#endif

#if defined(CWDEBUG) && !defined(DOXYGEN)
NAMESPACE_DEBUG_CHANNELS_START
channel_ct io("IO");
channel_ct evio("EVIO");
NAMESPACE_DEBUG_CHANNELS_END
#endif

namespace evio {

#ifdef DEBUGKEEPMEMORYBLOCKS
void StreamBuf::keep(MemoryBlock* mb)
{
  m_keep_v.push_back(mb);
}

void StreamBuf::dump()
{
  DoutEntering(dc::notice, "StreamBuf::dump()");
  for (auto&& mb : m_keep_v)
  {
    Dout(dc::notice, "[" << (void*)mb->block_start() << ", " << (void*)(mb->block_start() + mb->get_size()) << "> \"" << libcwd::buf2str(mb->block_start(), mb->get_size()) << "\".");
  }
}
#endif // DEBUGKEEPMEMORYBLOCKS

  // Constructor.
StreamBuf::StreamBuf(size_t requested_minimum_block_size, size_t buffer_full_watermark, size_t max_allocated_block_size) :
    StreamBufProducer(round_up_minimum_block_size(requested_minimum_block_size), buffer_full_watermark, max_allocated_block_size),
    m_device_counter(0)
{
  DoutEntering(dc::io, "StreamBuf(" << requested_minimum_block_size << ", " << buffer_full_watermark << ", " << max_allocated_block_size << ") [" << this << ']');
#ifdef CWDEBUG
  // m_minimum_block_size was set to the actual (possibly larger) minimum block size that is going to be used,
  // while requested_minimum_block_size is the value that is being requested.
  if (requested_minimum_block_size != m_minimum_block_size)
  {
    Dout(dc::warning, "Using a minimum block size of " << m_minimum_block_size << " bytes instead of requested " << requested_minimum_block_size << ". "
         "To suppress this warning use a power of two minus evio::block_overhead_c (" << block_overhead_c <<
         " bytes) for the minimum block size.");
  }
  // I just think this is a bit on the small side.
  if (m_minimum_block_size < 64)
  {
    Dout(dc::warning, "StreamBuf with a block_size of " << m_minimum_block_size << " which is smaller than 64 !");
    // Is your Protocol derived class returning a minimum_block_size() of zero? It is strongly suggested to use at LEAST 64.
    ASSERT(m_minimum_block_size > 0);
  }
#endif
  //===========================================================
  // Create first MemoryBlock.
  m_total_allocated = 0;
  m_get_area_block_node = m_put_area_block_node = create_memory_block(m_minimum_block_size);
  char* const start = m_get_area_block_node->block_start();
  setp(start, start + m_minimum_block_size);
  m_total_reset = 0;
  m_total_freed.store(0, std::memory_order_relaxed);
  m_total_read.store(0, std::memory_order_relaxed);
  StreamBufConsumer::setg(start, start, start);
  //===========================================================
  m_idevice = nullptr;
  m_odevice = nullptr;
}

// Calculate new block size for our output_buffer.
size_t StreamBufProducer::new_block_size() const
{
  size_t data_size_upper_bound = get_data_size_upper_bound();
  return utils::malloc_size(std::max(data_size_upper_bound, m_minimum_block_size) + sizeof(MemoryBlock)) - sizeof(MemoryBlock);
}

MemoryBlock* StreamBufProducer::create_memory_block(size_t block_size)
{
  Dout(dc::evio, "StreamBufProducer::create: allocating new memory block of size " << block_size);
  MemoryBlock* new_block = MemoryBlock::create(block_size);
  m_total_allocated += block_size;
#ifdef DEBUGSTREAMBUFSTATS
  ++m_number_of_created_blocks;
  m_created_block_size.push_back(block_size);
#endif
#ifdef DEBUGKEEPMEMORYBLOCKS
  keep(new_block);
#endif
  return new_block;
}

StreamBufProducer::int_type StreamBufProducer::overflow_a(int_type c)
{
  DoutEntering(dc::evio, "StreamBufProducer::overflow_a(" << char2str(c) << ") [" << this << ']');
#ifdef DEBUGDBSTREAMBUF
  printOn(std::cerr);
#endif
  if (c == static_cast<int_type>(EOF))
    return 0;
  std::streamsize available;
  char* cur_pptr = update_put_area(available);
  if (available == 0)
  {
    //===========================================================
    // Create a new MemoryBlock.
    size_t block_size = new_block_size();
    if (AI_UNLIKELY(get_allocated_upper_bound() + block_size > m_max_allocated_block_size)) // Max alloc reached?
    {
      block_size = utils::max_malloc_size(m_max_allocated_block_size - get_allocated_upper_bound() + sizeof(MemoryBlock)) - sizeof(MemoryBlock);
      if (block_size < m_minimum_block_size)
        return static_cast<int_type>(EOF);
    }
    MemoryBlock* new_block = create_memory_block(block_size);
    char* start = new_block->block_start();
    *start = c;   // Write data before calling setp_pbump.
    // Set m_next before calling setp_pbump; the consumer thread is guaranteed not to read it until sync_egptr() is called in setp_pbump() below.
    m_put_area_block_node->m_next = new_block;
    // Only after the next line, get_data_size_upper_bound() will return the correct value again.
    setp_pbump(start, start + block_size, 1);
        // Here the consumer thread may read m_next (and advance m_get_area_block_node to it).
    // Finally, point m_put_area_block_node to the new block.
    m_put_area_block_node = new_block;
    //===========================================================
  }
  else
  {
    *cur_pptr = c;
    pbump(1);
  }
#ifdef DEBUGDBSTREAMBUF
  printOn(std::cerr);
#endif
  return 0;
}

// Advance get area to next MemoryBlock.
char* StreamBufConsumer::release_memory_block(MemoryBlock*& get_area_block_node)
{
#ifdef DEBUGNEXTEGPTRSANITYCHECK
  std::lock_guard<std::mutex> lock(get_area_release_mutex);
#endif
  MemoryBlock* prev_get_area_block_node = get_area_block_node;
  get_area_block_node = get_area_block_node->m_next;
  char* start = get_area_block_node ? get_area_block_node->block_start() : nullptr;
  // Make sure to update m_last_gptr here, otherwise it is possible that after we free the memory block
  // that the producer thread reuses it-- and gets a pptr equal to the old m_last_gptr value that is still
  // pointing to that, now newly allocated, memory!
  store_last_gptr(start);
  Dout(dc::evio, "StreamBufConsumer::release: freeing memory block of size " << prev_get_area_block_node->get_size());
  // As only the consumer thread writes to m_total_freed, we can avoid a RMW operation here.
  std::streamsize new_total_freed = common().m_total_freed.load(std::memory_order_relaxed) + prev_get_area_block_node->get_size();
  prev_get_area_block_node->release();
  common().m_total_freed.store(new_total_freed, std::memory_order_release);
  return start;
}

// If m_resetting is true then reset the get area to the start of get_area_block_node.
// Then continue with the following:
//
// If last_pptr is not inside the current get_area_block_node and both gptr and egptr point to the
// end of that block (so the get area is empty) then advance the get_area_block_node to the next
// block node in the chain and set the get area pointers to the beginning of the new block. Then
// continue with the following:
//
// If last_pptr is not inside the current get_area_block_node then advance egptr to the end
// of the current get_area_block_node. Otherwise set egptr to m_last_pptr.
//
// This function updates cur_gptr to the current gptr, available to current egptr minus gptr and
// possibly advances get_area_block_node to get_area_block_node->next.
//
// Returns true iff the resulting egptr points the end of the resulting get_area_block_node and
// there is a next block (meaning, it is safe to read get_area_block_node->m_next; it is determined
// if this is the case by looking at whether or not m_last_pptr falls outside the current get_area_block_node).
bool StreamBufConsumer::update_get_area(MemoryBlock*& get_area_block_node, char*& cur_gptr_ref, std::streamsize& available)
{
#ifdef DEBUGSTREAMBUFSTATS
  ++m_number_of_calls_to_update_get_area;
#endif
  // Get a copy of the last 'sync-ed' pptr.
  bool is_resetting = common().m_resetting.load(std::memory_order_acquire);     // Synchronizes with the store release in update_put_area.
  char* last_pptr = common().m_last_pptr.load(std::memory_order_acquire);       // Make sure all data written to memory before m_last_pptr is visible.
  // Also needs to be acquire for the reset-synchronization otherwise the following could happen,
  //
  //                                                                                    // m_resetting = false, m_last_pptr = old_value (ie, block_start + 100).
  // [consumer_thread:update_get_area]
  // bool is_resetting = common().m_resetting.load(std::memory_order_acquire);          // is_resetting = false          ----.
  //                                                                                                                         |
  // [producer_thread:update_put_area]                                                                                       |
  // m_last_pptr.store(block_start, std::memory_order_relaxed);                         // m_last_pptr = block_start         |
  // m_resetting.store(true, std::memory_order_release);                                // m_resetting = true                |
  // [producer_thread:sync_egptr]                                                                                            |
  // m_last_pptr.store(cur_pptr, std::memory_order_release);                            // m_last_pptr = block_start + 10 (wrote 10 bytes after reset).
  //                                                           WRONG                                       |                 |
  // [consumer_thread:update_get_area]                           v                                         v                 |
  // char* last_pptr = common().m_last_pptr.load(std::memory_order_relaxed);            // last_pptr = block_start + 10      |
  // is_resetting |= (last_pptr == start && cur_gptr != start);                         // is_resetting = false              |
  // if (!is_resetting && common().m_resetting.load(std::memory_order_acquire))         // m_resetting is false           <--'
  //
  // Code below uses a reset value for last_pptr while is_resetting is not set.
  //
  // This can not happen when the read of block_start + 10 to last_pptr is acquire
  // as that then will synchronize with the m_resetting = true that is done
  // before the update in sync_egptr.

  char* cur_gptr = gptr();            // Just store the current value of gptr in cur_gptr (case 1 and 2).

  char* start = get_area_block_node->block_start();
  char* end = start + get_area_block_node->get_size();

  // The following line takes care of a reset value of m_last_pptr (to block_start) before m_resetting was set to true yet (or simply not visible yet here).
  is_resetting |= (last_pptr == start && cur_gptr != start);

  // Unlikely race condition. This takes care of the situation the initial load acquire
  // of m_resetting was false, but the subsequent load acquire of m_last_pptr is a reset-value
  // already larger than block_start (in sync_egptr), so is_resetting wasn't set to true in the
  // previous line. Since sync_egptr uses store release, that is only possible when the store
  // true to m_resetting is now visible.
  // The load of m_resetting here must be acquire or it could still get a false value,
  // for example,
  //                                                                                    // m_resetting = false, m_last_pptr = old_value (ie, block_start + 100).
  // [consumer_thread:update_get_area]                                                                                            |
  // bool is_resetting = common().m_resetting.load(std::memory_order_acquire);          // is_resetting = false  ---------.       |
  // char* last_pptr = common().m_last_pptr.load(std::memory_order_acquire);            // last_pptr = block_start + 100  |       |
  // [producer_thread:update_put_area]                                                                                    |       |
  // m_last_pptr.store(block_start, std::memory_order_relaxed);                         // m_last_pptr = block_start      |       |
  // m_resetting.store(true, std::memory_order_release);                                // m_resetting = true     -----.  |       |
  // [consumer_thread:update_get_area]                                                                                 |  |       |
  // bool is_resetting = common().m_resetting.load(std::memory_order_acquire);          // is_resetting = false   <----+--'       |
  // if (!is_resetting && common().m_resetting.load(std::memory_order_relaxed))         // m_resetting is true    <----'          |
  // {                                                    WRONG -^                                                                |
  //   is_resetting = true;                                                                                                       |
  //   last_pptr = common().m_last_pptr.load(std::memory_order_relaxed);                // last_pptr = block_start + 100      <---'
  //
  // Code below uses an old pre-reset value for last_pptr while is_resetting is true.
  //
  // This can not happen when the load of m_resetting is true is acquire
  // as that then will synchronize with the m_last_pptr = block_start that is
  // done before that.
  if (AI_UNLIKELY(!is_resetting && common().m_resetting.load(std::memory_order_acquire)))
  {
    is_resetting = true;
    // As in the example above, here we pick up the reset value of m_last_pptr that became
    // visible with the load acquire of m_resetting in the line above.
    last_pptr = common().m_last_pptr.load(std::memory_order_acquire);
    // Reading m_last_pptr must always be acquire in order to make sure that the data
    // written to the buffer up til that value is also visible, before we attempt to read it.
  }

  // At this point is_resetting is set if and only if last_pptr is the (a) value of pptr *after* the reset.
  // Thus, if is_resetting is set than bytes between start and last_pptr is valid, unread data;
  // while if is_resetting is not set then bytes between cur_gptr and last_pptr is valid, unread data.

  // There are now three possible cases:
  //
  // 1) We're in the same block as the put area.
  //
  //   |=========================================|
  //   ^        ^                    ^           ^
  //   |        |                    |           |
  // start   cur_gptr            last_pptr      end
  //
  // 2) We're not in the same block as the put area.
  //
  //   |================get=area=================|          |==============put=area===============|
  //   ^        ^                                ^                      ^
  //   |        |                                |                      |
  // start   cur_gptr                           end                 last_pptr
  //
  // 3) We're in the same block as the put area, but the buffer is empty and we need to reset to the beginning of the buffer:
  //
  //   |=========================================|
  //   ^     ^           ^                       ^      is_resetting == true
  //   |     |           |                       |
  // start  last_pptr  cur_gptr                 end
  //    <--->           egptr
  //      \__ unread data.

#ifdef DEBUGEVENTRECORDING
  RecordingData* data = new (common().recording_pool) RecordingData(cur_gptr - start, start, end - start);
  updating_get_area(data);
#endif
  if (is_resetting)             // Do we have to reset the get area to the beginning of the buffer?
  //---------------------------------------------------------------------------
  // Case 3
  //
  {
#ifdef DEBUGSTREAMBUFSTATS
    ++m_number_of_get_area_resets;
#endif
    Dout(dc::evio, "update_get_area: resetting get area.");
    common().m_last_gptr.store(start, std::memory_order_relaxed);       // We are going to reset gptr to start.
#ifdef DEBUGEVENTRECORDING
    RecordingData* data = new (common().recording_pool) RecordingData(read_stream_offset, start, 0);
    resetting_get_area(data);
#endif
    common().m_resetting.store(false, std::memory_order_release);       // Flush m_last_gptr before resetting m_resetting.

    // Reset gptr to the beginning of the current memory block.
    cur_gptr = start;
  }
  //
  // 3) Here we reached the following situation:
  //
  //   |=========================================|
  //   ^     ^                                   ^      m_resetting == true
  //   |     |                                   |
  //cur_gptr |
  // start  last_pptr                           end
  //    <--->
  //      \__ unread data.
  //
  // Where the meaning of cur_gptr rather is 'next gptr', we will use cur_gptr below to change gptr (and egptr will be set to last_pptr).
  // This case has now become a case 1, so we continue as normal.
  //
  //---------------------------------------------------------------------------

  char* cur_egptr = end;
  bool case1;
  for (;;)
  {
    case1 = start <= last_pptr && last_pptr <= end;     // Does last_pptr fall in the current get area block?
    if (case1)
      cur_egptr = last_pptr;                            // We will use cur_egptr below to change egptr.
    // The immediately available number of bytes in the get area (after the update below).
    available = cur_egptr - cur_gptr;
#ifdef CWDEBUG
    if (AI_UNLIKELY(available < 0))
    {
      DoutFatal(dc::core, "cur_gptr = " << (cur_gptr - start) << "; cur_egptr = " << (cur_egptr - start) <<
          "; last_pptr = " << (last_pptr - start) << "; is_resetting = " << is_resetting << "; m_resetting = " << common().m_resetting);
    }
#endif

    if (available != 0)
      break;

    if (case1)
    {
      // Update get area and always return false - even when gptr is at the end of the block.
      setg(start, cur_gptr, cur_egptr);
      cur_gptr_ref = cur_gptr;
      return false;     // There isn't a next block.
    }

    // This a case 2 therefore get_area_block_node->m_next is non-null and we can safely call release_memory_block(get_area_block_node).
    // Update get_area_block_node to point to the next block and return the new start.
    cur_gptr = start = release_memory_block(get_area_block_node);
    cur_egptr = end = start + get_area_block_node->get_size();
    // Continue from the start of the loop.
    // Since cur_gptr is now start, available will be non-zero unless last_pptr == start, in which case case1 becomes true.
    // So this jump back only happens once.
  }

  // Finally, update the get area.
  setg(start, cur_gptr, cur_egptr);

  // Not being a 'case1' must mean that we have multiple blocks.
  // Note that accessing m_next is only safe when case1 is false.
  ASSERT(case1 || get_area_block_node->m_next);

  // Return true if the current egptr points to the end of the block and there is a next block.
  cur_gptr_ref = cur_gptr;
  return cur_egptr == end && !case1;
}

// Get thread.
int StreamBufConsumer::underflow_a()
{
  DoutEntering(dc::evio, "StreamBuf::underflow_a() [" << this << ']');
#ifdef DEBUGDBSTREAMBUF
  printOn(std::cerr);
#endif
#ifdef DEBUGSTREAMBUFSTATS
  ++m_number_of_calls_to_underflow_a;
#endif
  char* cur_gptr;
  std::streamsize available;
  update_get_area(m_get_area_block_node, cur_gptr, available);
  int result = 0;
  if (available == 0)
  {
    // There is nothing to read anymore at the moment.
    store_last_gptr(cur_gptr);
    Dout(dc::evio, "Returning EOF");
    result = EOF;
  }
#ifdef DEBUGDBSTREAMBUF
  printOn(std::cerr);
#endif
  Dout(dc::evio, "Returning 0 (available " << available << " bytes).");
  return result;
}

// Note: a putback is not really thread-safe when the character
// that was previously read is already part of a complete message
// that is being decoded; nor will the putback alter the previous
// message when we get here (that is thread-safe, but different
// from when we were not by coincidence on the edge of a block).
//
// The only safe way to use putback is therefore to read a single
// character using sbumpc, decide we don't want it and put the
// character that we just read back so it can be part of the *next*
// message. In this case pbackfail will NOT be called.
//
// If one reads a character with sgetn (or from an istream) resulting
// in xsgetn_a() being called and the that results in the buffer
// going empty - then that can cause a buffer reset, resetting the
// put area to the start of the current memory block. Putting back
// a character is then never safe because it basically writes into
// the (new) put area.
StreamBuf::int_type StreamBufProducer::pbackfail(int_type c)
{
  DoutEntering(dc::notice, "pbackfail(" << libcwd::char2str(c) << ") [" << this << ']');
  if (c == static_cast<int_type>(EOF))
  {
#ifdef DEBUGDBSTREAMBUF
    printOn(std::cerr);
#endif
    return 0;
  }
  DoutFatal(dc::fatal, "Do not use sputbackc. It is not thread-safe.");
  return 0;
}

// Number of characters available for reading from this buffer (output_buffer).
std::streamsize StreamBufConsumer::showmanyc_a()
{
  // showmanyc() is not supported because I don't think it is needed and it would cost extra CPU time to make it work.
  ASSERT(false);        // m_buffer_size_minus_unused_in_last_block isn't updated at the moment.
  //return m_buffer_size_minus_unused_in_last_block - unused_in_first_block();
  return 0;
}

//Get Thread.
std::streamsize StreamBufConsumer::xsgetn_a(char* s, std::streamsize const n)
{
  DoutEntering(dc::evio|continued_cf, "StreamBuf::xsgetn_a(s, " << n << ") [" << this << "]... ");
#ifdef DEBUGDBSTREAMBUF
  printOn(std::cerr);
#endif
#ifdef DEBUGSTREAMBUFSTATS
  ++m_number_of_calls_to_xsgetn_a;
#endif
  std::streamsize remaining = n;
  while (remaining > 0)
  {
    char* cur_gptr;
    std::streamsize available;
    bool at_end_and_has_next_block = update_get_area(m_get_area_block_node, cur_gptr, available);
    ASSERT(available >= 0);
    // If at_end_and_has_next_block is true then egptr is set to the very end of the
    // current memory block (m_get_area_block_node, which might have been changed too!)
    // and m_get_area_block_node->m_next is non-null.
    std::streamsize len = 0;
    if (available != 0)
    {
      len = std::min(available, remaining);
#ifdef DEBUGEVENTRECORDING
      RecordingData* data = new (common().recording_pool) RecordingData(read_stream_offset, cur_gptr, len);
      record_memcpy(data, s);
#else
      std::memcpy(s, cur_gptr, len);
#endif
      common().gbump(len);              // Do not update m_total_read, that happens at the end of this function.
      s += len;
      available -= len;
      remaining -= len;
    }
    if (!at_end_and_has_next_block)     // Leave if egptr != block end, or when there isn't a next block.
    {
      if (available == 0)       // Buffer empty?
        store_last_gptr(cur_gptr + len);
      break;
    }
    if (available == 0)                 // gptr == egptr == block end?
    {
      char* start = release_memory_block(m_get_area_block_node);
      setg(start, start, start);
    }
  }
  std::streamsize new_total_read = common().m_total_read.load(std::memory_order_relaxed) + n - remaining;
  common().m_total_read.store(new_total_read, std::memory_order_release);
  Dout(dc::finish, " = " << (n - remaining));
#ifdef DEBUGDBSTREAMBUF
  printOn(std::cerr);
#endif
#ifdef DEBUGSTREAMBUFSTATS
  if (n - remaining == 0)
    ++m_xsgetn_a_read_zero_bytes;
  if (remaining == 0)
    ++m_xsgetn_a_read_all_requested_bytes;
#endif
  return n - remaining;
}

char* StreamBufProducer::update_put_area(std::streamsize& available)
{
  char* block_start = std::streambuf::pbase();
  char* cur_pptr = std::streambuf::pptr();
  if (cur_pptr != block_start &&                                        // Don't start a reset cycle when pptr is already at the start of the block ;).
      !m_resetting.load(std::memory_order_acquire) &&                   // If m_resetting then the put area was reset, but the get area wasn't yet;
                                                                        // don't reset again until it was. This read must be acquire to make sure the write
                                                                        // to last_gptr is visible too.
      // Before m_last_gptr actually gets set (to gptr when when there are no more bytes available for reading),
      // the most sensible value might be block_start - but in that case this comparison will evaluate to false
      // since cur_pptr != block_start. Therefore we might as well initialize m_last_gptr to nullptr in the
      // streambuf constructor.
      cur_pptr == m_last_gptr.load(std::memory_order_acquire))          // If this happens while m_resetting is false then the buffer is truely empty (gptr == pptr).
  {
    Dout(dc::evio, "update_put_area: resetting put area.");
#ifdef DEBUGEVENTRECORDING
    RecordingData* data = new (recording_pool) RecordingData(write_stream_offset, cur_pptr, 0);
    resetting_put_area(data);
#endif
    m_last_pptr.store(block_start, std::memory_order_relaxed);          // Initialize m_last_pptr that the consumer thread will use once it resets itself.
                                                                        // This can be relaxed because there is nothing written to memory before this store
                                                                        // that the consumer needs to see when it reads this value.

    // A value of nullptr means 'block_start', but will prevent the producer thread to write to it
    // until the consumer thread did reset too. Nor will the producer thread reset again until that happened.
    m_resetting.store(true, std::memory_order_release);                 // Atomically signal the consumer thread that it must reset.
                                                                        // This write must be release to flush the write of m_last_pptr, otherwise it
                                                                        // is possible that the consumer thread would use an old (not reset) pptr value
                                                                        // as "reset" pptr value and therefore think there is more data to read then
                                                                        // there actually is.
#ifdef DEBUGNEXTEGPTRSANITYCHECK
    sanity_check();
#endif
    m_total_reset += cur_pptr - block_start;
    std::streambuf::pbump(block_start - cur_pptr);                      // Reset ourselves.
    cur_pptr = block_start;
  }
  available = std::streambuf::epptr() - cur_pptr;
  return cur_pptr;
}

std::streamsize StreamBufProducer::xsputn_a(char const* s, std::streamsize const n)
{
  DoutEntering(dc::evio|continued_cf, "StreamBuf::xsputn_a(\"" << buf2str(s, n) << "\", " << n << ") [" << this << "] ");
#ifdef DEBUGDBSTREAMBUF
  printOn(std::cerr);
#endif
  std::streamsize remaining = n;
  while (remaining > 0)
  {
    std::streamsize available;
    char* cur_pptr = update_put_area(available);
    if (available > 0)
    {
      std::streamsize len = std::min(available, remaining);
#ifdef DEBUGEVENTRECORDING
      RecordingData* data = new (recording_pool) RecordingData(write_stream_offset, cur_pptr, len);
      record_memcpy(data, s);
#else
      std::memcpy(cur_pptr, s, len);            // Write to buffer before calling pbump.
#endif
      pbump(len);
      s += len;
      remaining -= len;
    }
    if (remaining > 0)                          // pptr == epptr (block end) AND we still need to write more?
    {
      //===========================================================
      // Create a new MemoryBlock.
      size_t block_size = new_block_size();
      if (AI_UNLIKELY(get_allocated_upper_bound() + block_size > m_max_allocated_block_size)) // Max alloc reached?
      {
        block_size = utils::max_malloc_size(m_max_allocated_block_size - get_allocated_upper_bound() + sizeof(MemoryBlock)) - sizeof(MemoryBlock);
        if (block_size < m_minimum_block_size)
          return static_cast<int_type>(EOF);
      }
      MemoryBlock* new_block = create_memory_block(block_size);
      char* start = new_block->block_start();
      // Set m_next before calling setp; the consumer thread is guaranteed not to read it until sync_egptr() is called in setp() below.
      m_put_area_block_node->m_next = new_block;
      // Only after the next line, get_data_size_upper_bound() will return the correct value again.
      setp(start, start + block_size);
          // Here the consumer thread may read m_next (and advance m_get_area_block_node to it).
      // Finally, point m_put_area_block_node to the new block.
      m_put_area_block_node = new_block;
      //===========================================================
    }
  }
  Dout(dc::finish, "= " << (n - remaining));
#ifdef DEBUGDBSTREAMBUF
  printOn(std::cerr);
#endif
  return n - remaining;
}

//============================================================================
// Redirect virtual methods of streambuf.

// The virtual functions are from the point of view of the std::stream buf,
// which mean that if they access the get area then they should access
// our m_input_streambuf.

std::streamsize StreamBuf::showmanyc()
{
  return m_input_streambuf->showmanyc_a();
}

std::streambuf::int_type StreamBuf::underflow()
{
  return m_input_streambuf->underflow_a();
}

std::streamsize StreamBuf::xsgetn(char* s, std::streamsize n)
{
  return m_input_streambuf->xsgetn_a(s, n);
}

std::streambuf::int_type StreamBuf::overflow(int_type c)
{
  return static_cast<StreamBuf*>(this)->overflow_a(c);
}

std::streamsize StreamBuf::xsputn(char const* s, std::streamsize n)
{
  return static_cast<StreamBuf*>(this)->xsputn_a(s, n);
}

//============================================================================

void StreamBuf::reduce_buffer()
{
  DoutEntering(dc::notice, "StreamBuf::reduce_buffer");
  // The buffer if empty, so there is only one block (get_area_block_node == put_area_block_node).
  if (m_get_area_block_node->get_size() > m_minimum_block_size)
  {
    //===========================================================
    // Replace first and only MemoryBlock.
#ifdef DEBUGNEXTEGPTRSANITYCHECK
    std::lock_guard<std::mutex> lock(get_area_release_mutex);
#endif
    MemoryBlock* prev_get_area_block_node = m_get_area_block_node;
    m_put_area_block_node = m_get_area_block_node = create_memory_block(m_minimum_block_size);
    Dout(dc::notice, "reduce_buffer: freeing memory block of size " << prev_get_area_block_node->get_size());
    std::streamsize new_total_freed = m_total_freed.load(std::memory_order_relaxed) + prev_get_area_block_node->get_size();
    prev_get_area_block_node->release();
    m_total_freed.store(new_total_freed, std::memory_order_release);
    //===========================================================
  }
  // Reset the empty buffer.
  char* start = m_get_area_block_node->block_start();
  StreamBufConsumer::setg(start, start, start);
  // After the call to setp, unused_in_last_block() has become m_minimum_block_size.
  // m_total_reset keeps track of the total amount that unused_in_last_block() was incremented
  // by resets of the buffer.
  m_total_reset += m_minimum_block_size - unused_in_last_block();
  setp(start, start + m_minimum_block_size);
  store_last_gptr(start);
}

int StreamBufProducer::sync()
{
  // m_odevice points to the device whose constructor this buffer was passed to.
  return m_odevice->sync();
}

// Read thread of linked device.
void StreamBufProducer::flush()
{
  // m_odevice points to the device whose constructor this buffer was passed to.
  m_odevice->restart_if_non_active();
}

bool StreamBuf::release(FileDescriptor const* device)
{
  // StreamBuf should always be used as base class of InputBuffer, OutputBuffer or LinkBuffer only.
  ASSERT(m_device_counter > 0);
  if (--m_device_counter == 0)
  {
    delete this;
    return true;
  }
  else if (device == m_odevice)
  {
    // This can only be the case when this is a bouncer.
    ASSERT(device == m_idevice);

    // If Device1 and Device2 are the same device (a bouncer) then
    // the situation is:
    //
    //   InputDevice - - -> Streambuf < - - - OutputDevice (inhibit_deletion() was NOT called!)
    //       |                  |                  |
    //       |                  v                  |
    //       |              LinkBuffer             |
    //        \                                   /
    //         \                                 /
    //          `--------->Bounce Device<-------'
    //
    // And we need to simply reset the appropriate m_idevice / m_odevice without
    // calling allow_deletion(). We can't know if this we're being called from
    // the destructor of InputDevice or OutputDevice but that shouldn't matter.
    // Both will be called immediately after another. So lets just set both
    // pointers to nullptr (I don't think they will be used anymore).
    m_idevice = nullptr;
    m_odevice = nullptr;
  }
  else
  {
    // When m_device_counter became 2, the ref count of m_odevice was increased.
    // Therefore it is impossible that m_odevice would be deleted (calling this
    // function) before allow_deletion() is called - which also happens by this
    // function. Hence, this function will always be called first with,
    ASSERT(device == m_idevice);
    // Therefore we must go from this situation:
    //
    //               <----- m_idevice
    //                      m_odevice ------>
    //   InputDevice - - -> Streambuf < - - - OutputDevice (inhibit_deletion() was called on this device).
    //       |                  |                  |
    //       v                  v                  v
    //    Device1           LinkBuffer          Device2
    //
    // To this situation:
    //
    //          nullptr <-- m_idevice
    //                      m_odevice ------>
    //                      Streambuf < - - - OutputDevice (allow_deletion() was called).
    //                          |                  |
    //                          v                  v
    //                      LinkBuffer         Device2
    //
    // (where the destructor InputDevice (base of Device1) is calling us).

    // Resetting the device pointer is necessary because of `sync' and `flush'.
    m_idevice = nullptr;
    Dout(dc::io|continued_cf, "this = " << this << "; StreamBuf::release(" << (void*)device << "), ");
    m_odevice->allow_deletion();
    Dout(dc::finish, m_device_counter << "output device left: " << m_odevice);
  }
  return false;
}

void StreamBuf::set_input_device(InputDevice* device)
{
  // Don't pass a StreamBuf to more than one device.
  // Also note set_input_device should only be called from InputDevice::input, don't call it directly.
  ASSERT(!m_idevice);
  if (++m_device_counter == 2)
  {
    // Inhibit the deletion of the output device iff the input device and output device aren't the same device (a bouncer).
    if (static_cast<FileDescriptor*>(device) != static_cast<FileDescriptor*>(m_odevice))
    {
      CWDEBUG_ONLY(int count =) m_odevice->inhibit_deletion();
      Dout(dc::io, "this = " << this << "; Calling StreamBuf::set_input_device(" << device <<
          "); incremented ref count of output device [" << m_odevice << "] (now " << (count + 1) << ").");
    }
  }
  m_idevice = device;
}

void StreamBuf::set_output_device(OutputDevice* device)
{
  // Don't pass a StreamBuf to more than one device.
  // Also note that set_output_device should only be called from the constructor of OutputBuffer or LinkBuffer. Don't call it directly.
  ASSERT(!m_odevice);
  if (++m_device_counter == 2)
  {
    // Inhibit the deletion of the output device iff the input device and output device aren't the same device (a bouncer).
    if (static_cast<FileDescriptor*>(device) != static_cast<FileDescriptor*>(m_idevice))
    {
      CWDEBUG_ONLY(int count =) device->inhibit_deletion();
      Dout(dc::io, "this = " << this << "; Calling StreamBuf::set_output_device(" << device <<
          "); incremented ref count of output device [" << device << "] (now " << (count + 1) << ").");
    }
  }
  m_odevice = device;
}

void StreamBuf::do_restart_input_device_if_needed()
{
  if (buffer_not_full_anymore())
  {
    Dout(dc::notice, "The buffer is not full anymore [" << this << "]");
    m_buffer_was_full.store(false, std::memory_order_relaxed);
    if (m_idevice)
      m_idevice->start_input_device();
  }
}

#ifdef DEBUGDBSTREAMBUF
void StreamBuf::printOn(std::ostream& os) const
{
  os << "----------------------------------------------------------------------\n";
  os << "minimum_block_size = " << m_minimum_block_size << "; "
        "buffer_full_watermark = " << m_buffer_full_watermark << "; "
        "max_allocated_block_size = " << m_max_allocated_block_size;
  int current_number_of_blocks = 0;
  for (MemoryBlock* block_node = m_get_area_block_node; block_node; block_node = block_node->m_next)
    ++current_number_of_blocks;
  os << "; current_number_of_blocks = " << current_number_of_blocks << '\n';
  os << "Block nodes:\n";
  unsigned int block_count = 0;
  size_t total_size = 0;
  os << "Start\t\tSize\n";
  for (MemoryBlock* block_node = m_get_area_block_node; block_node; block_node = block_node->m_next)
  {
    os << (void*)block_node->block_start() << '\t' << block_node->get_size() << '\n';
    total_size += block_node->get_size();
    ++block_count;
  }
  os << "Total size: " << total_size << '\n';
  // Get a get- and put- area snapshot.
  char* cur_eback;
  char* cur_gptr;
  char* cur_egptr;
  char* cur_pbase;
  char* cur_pptr;
  char* cur_epptr;
  {
    cur_eback = eback();
    cur_gptr = gptr();
    cur_egptr = egptr();
    cur_pbase = pbase();
    cur_pptr = pptr();
    cur_epptr = epptr();

    size_t uifb = unused_in_first_block();
    size_t uilb = unused_in_last_block();
    size_t data_size = get_data_size();
    if (total_size != uifb + data_size + uilb)
      DoutFatal(dc::core, "Inconsistent get_data_size (" << total_size << " != " << uifb << " + " << data_size << " + " << uilb << ")!");
  }
  os << "get_area_block_node = " << (void*)m_get_area_block_node;
  os << "; put_area_block_node = " << (void*)m_put_area_block_node << '\n';
  os << "get area: " << (void*)cur_eback << " - " << (void*)cur_gptr << "(" << cur_gptr - cur_eback << ")" <<
    " - " << (void*)cur_egptr << "(" << cur_egptr - cur_eback << ")";
#if CWDEBUG_ALLOC
  alloc_ct const* eback_alloc = find_alloc(cur_eback);
  ASSERT(eback_alloc);
  os << "\t[ " << eback_alloc->start() << " (" << eback_alloc->size() << ") ]";
#endif
  os << '\n';
  os << "put area: " << (void*)cur_pbase << " - " << (void*)cur_pptr << "(" << cur_pptr - cur_pbase << ")" <<
    " - " << (void*)cur_epptr << "(" << cur_epptr - cur_pbase << ")";
#if CWDEBUG_ALLOC
  alloc_ct const* pbase_alloc = find_alloc(cur_pbase);
  ASSERT(pbase_alloc);
  os << "\t[ " << pbase_alloc->start() << " (" << pbase_alloc->size() << ") ]";
#endif
  os << '\n';
#if CWDEBUG_ALLOC
  if ((char*)eback_alloc->start() + sizeof(MemoryBlock) != cur_eback)
    DoutFatal(dc::core, "get area points to non-allocated block !");
  alloc_ct const* gptr_m1_alloc = find_alloc(cur_gptr - 1);
  ASSERT(gptr_m1_alloc);
  if (cur_gptr != cur_eback && (char*)gptr_m1_alloc->start() + sizeof(MemoryBlock) != cur_eback)
    DoutFatal(dc::core, "get area get pointer points outside allocated block !");
  alloc_ct const* egptr_m1_alloc = find_alloc(cur_egptr - 1);
  ASSERT(egptr_m1_alloc);
  if (cur_egptr != cur_eback && (char*)egptr_m1_alloc->start() + sizeof(MemoryBlock) != cur_eback)
    DoutFatal(dc::core, "end of get area points outside allocated block !");
  if ((char*)pbase_alloc->start() + sizeof(MemoryBlock) != cur_pbase)
    DoutFatal(dc::core, "put area points to non-allocated block !");
  alloc_ct const* pptr_m1_alloc = find_alloc(cur_pptr - 1);
  ASSERT(pptr_m1_alloc);
  if (cur_pptr != cur_pbase && (char*)pptr_m1_alloc->start() + sizeof(MemoryBlock) != cur_pbase)
    DoutFatal(dc::core, "put area put pointer points outside allocated block !");
  alloc_ct const* epptr_m1_alloc = find_alloc(cur_epptr - 1);
  ASSERT(epptr_m1_alloc);
  if (cur_epptr != cur_pbase && (char*)epptr_m1_alloc->start() + sizeof(MemoryBlock) != cur_pbase)
    DoutFatal(dc::core, "end of put area points outside allocated block !");
#endif
  os << "Total string length: " << total_size - (cur_gptr - cur_eback) - (cur_epptr - cur_pptr) << '\n';
  for (MemoryBlock* block_node = m_get_area_block_node; block_node; block_node = block_node->m_next)
  {
    os << "[" << (void*)block_node << "] ";
    if (block_node == m_get_area_block_node && block_node == m_put_area_block_node)
    {
      if (cur_pptr >= cur_gptr)
        os << "\"" << buf2str(cur_gptr, cur_pptr - cur_gptr) << "\"\n";     // Print from gptr() to pptr().
      else if (is_resetting())
        os << "\"" << buf2str(block_node->block_start(), cur_pptr - cur_pbase) << "\" (resetting)\n";     // Print from start of buffer to pptr().
      else
        os << "INVALID RANGE\n";
    }
    else if (block_node == m_get_area_block_node)
      os << "\"" << buf2str(cur_gptr, block_node->get_size() - (cur_gptr - cur_eback)) << '\n';      // Print from igptr() to the end of the buffer.
    else if (block_node == m_put_area_block_node)
      os << buf2str(block_node->block_start(), cur_pptr - cur_pbase) << "\"\n";   // Print from start of buffer to pptr().
    else
      os << buf2str(block_node->block_start(), block_node->get_size()) << '\n';         // Print the whole buffer.
  }
  if (cur_eback != m_get_area_block_node->block_start() ||
      cur_pbase != m_put_area_block_node->block_start() ||
      cur_epptr != cur_pbase + m_put_area_block_node->get_size() ||
      (m_get_area_block_node == m_put_area_block_node && !is_resetting() && cur_egptr > cur_pptr) ||
      cur_egptr > cur_eback + m_get_area_block_node->get_size() ||
      cur_gptr < cur_eback || cur_gptr > cur_egptr ||
      cur_pptr < cur_pbase || cur_pptr > cur_epptr)
    DoutFatal(dc::core, "Pointers inconsistent");
  os << "----------------------------------------------------------------------" << std::endl;
  ASSERT(os.good());
}
#endif

#ifdef DEBUGEVENTRECORDING

// Read from the buffer: copy data from `data->start' to `to'.
void StreamBufConsumer::record_memcpy(RecordingData* data, char* to)
{
  data->m_type = memcpy_reading;
  {
    std::lock_guard<std::mutex> lock(common().recording_mutex);
    std::memcpy(to, data->m_start, data->m_length);
    common().recording_buffer.push_back(data);
  }
  read_stream_offset += data->m_length;
}

// Write data to the buffer: copy data from `from' to `data->start`.
void StreamBufProducer::record_memcpy(RecordingData* data, char const* from)
{
  data->m_type = memcpy_writing;
  {
    std::lock_guard<std::mutex> lock(recording_mutex);
    std::memcpy(const_cast<char*>(data->m_start), from, data->m_length);
    recording_buffer.push_back(data);
  }
  write_stream_offset += data->m_length;
}

void StreamBufProducer::resetting_put_area(RecordingData* data)
{
  data->m_type = put_area_reset;
  std::lock_guard<std::mutex> lock(recording_mutex);
  recording_buffer.push_back(data);
}

void StreamBufConsumer::resetting_get_area(RecordingData* data)
{
  data->m_type = get_area_reset;
  std::lock_guard<std::mutex> lock(common().recording_mutex);
  common().recording_buffer.push_back(data);
}

void StreamBufConsumer::updating_get_area(RecordingData* data)
{
  data->m_type = get_area_update;
  std::lock_guard<std::mutex> lock(common().recording_mutex);
  common().recording_buffer.push_back(data);
}

std::ostream& operator<<(std::ostream& os, RecordingData const& data)
{
  static char chars[129] = "abcdefghijklmnopqrstuvwxyz789012ABCDEFGHIJKLMNOPQRSTUVWXYZ&*()!\nabcdefghijklmnopqrstuvwxyz789012ABCDEFGHIJKLMNOPQRSTUVWXYZ&*()!\n";
  switch (data.m_type)
  {
    case memcpy_reading:
      os << (void*)data.m_start << " -read--> ";
      os << "(" << data.m_stream_offset << " [" << data.m_length << "]) expecting: \"" << std::string(chars + data.m_stream_offset % 64, data.m_length) << "\".";
      break;
    case memcpy_writing:
      os << (void*)data.m_start << " <-write- ";
      os << "(" << data.m_stream_offset << " [" << data.m_length << "]) \"" << std::string(chars + data.m_stream_offset % 64, data.m_length) << "\".";
      break;
    case put_area_reset:
      os << "Put area reset; pptr = m_last_gptr == " << (void*)data.m_start;
      break;
    case get_area_reset:
      os << "Get area reset; m_last_gptr = " << (void*)data.m_start;
      break;
    case stored_last_gptr:
      os << "store_last_gptr(): m_last_gptr = " << (void*)data.m_start;
      break;
    case get_area_update:
      os << "Entering update_get_area: get area is now: [" << (void*)data.m_start << ", " << (void*)(data.m_start + data.m_stream_offset) << ", " << (void*)(data.m_start + data.m_length) << ">.";
      break;
  }
  return os;
}

#endif // DEBUGEVENTRECORDING

#ifdef DEBUGSTREAMBUFSTATS

void StreamBufProducer::dump_stats() const
{
  std::cout << "m_number_of_created_blocks = " << m_number_of_created_blocks << std::endl;
  std::map<size_t, int> bsm;
  for (size_t s : m_created_block_size)
    bsm[s]++;
  char const* separator = "m_created_block_size: ";
  for (auto p : bsm)
  {
    std::cout << separator << p.first << ": " << p.second;
    separator = ", ";
  }
  std::cout << std::endl;
  std::cout << "m_total_allocated = " << m_total_allocated << std::endl;
  std::cout << "m_total_reset = " << m_total_reset << std::endl;
}

void StreamBufConsumer::dump_stats() const
{
  std::cout << "m_number_of_calls_to_update_get_area = " << m_number_of_calls_to_update_get_area << std::endl;;
  std::cout << "m_number_of_get_area_resets = " << m_number_of_get_area_resets << std::endl;
  std::cout << "m_number_of_calls_to_store_last_gptr = " << m_number_of_calls_to_store_last_gptr << std::endl;
  std::cout << "m_number_of_calls_to_xsgetn_a = " << m_number_of_calls_to_xsgetn_a << std::endl;
  std::cout << "m_number_of_calls_to_underflow_a = " << m_number_of_calls_to_underflow_a << std::endl;
  std::cout << "m_xsgetn_a_read_zero_bytes = " << m_xsgetn_a_read_zero_bytes << std::endl;
  std::cout << "m_xsgetn_a_read_all_requested_bytes = " << m_xsgetn_a_read_all_requested_bytes << std::endl;
  std::cout << "m_total_freed = " << common().m_total_freed << std::endl;
}

#endif // DEBUGSTREAMBUFSTATS

std::ostream& operator<<(std::ostream& os, StreamBufProducer* sb)
{
  return os << (void*)static_cast<StreamBuf*>(sb);
}

std::ostream& operator<<(std::ostream& os, StreamBufConsumer* sb)
{
  return os << (void*)&static_cast<StreamBuf&>(sb->common());
}

#ifndef DEBUGDBSTREAMBUF
std::ostream& operator<<(std::ostream& os, StreamBuf* sb)
{
  return os << (void*)sb;
}
#endif

} // namespace evio
