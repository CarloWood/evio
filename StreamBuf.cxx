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
using namespace libcwd;
#else
#undef DEBUGDBSTREAMBUF
#endif

#if defined(CWDEBUG) && !defined(DOXYGEN)
NAMESPACE_DEBUG_CHANNELS_START
channel_ct io("IO");
channel_ct evio("EVIO");
NAMESPACE_DEBUG_CHANNELS_END
#endif

namespace evio {

StreamBuf::StreamBuf(size_t minimum_block_size, size_t buffer_full_watermark, size_t max_allocated_block_size) :
  m_minimum_block_size(minimum_block_size), m_buffer_full_watermark(buffer_full_watermark), m_max_allocated_block_size(max_allocated_block_size),
  m_buffer_size_minus_unused_in_last_block(0), m_device_counter(0)
{
  DoutEntering(dc::io, "StreamBuf(" << minimum_block_size << ", " << buffer_full_watermark << ", " << max_allocated_block_size << ") [" << this << ']');
  SingleThread type;
  size_t block_size = utils::malloc_size(m_minimum_block_size + sizeof(MemoryBlock)) - sizeof(MemoryBlock);
#ifdef CWDEBUG
  if (block_size != m_minimum_block_size)
  {
    Dout(dc::warning, "Using a minimum block size of " << block_size << " bytes instead of requested " << m_minimum_block_size << ". "
         "To suppress this warning use a power of two minus " << (sizeof(MemoryBlock) + CW_MALLOC_OVERHEAD) << " bytes for the minimum block size.");
  }
  // I just think this is a bit on the small side.
  if (block_size < 64)
    Dout(dc::warning, "StreamBuf with a block_size smaller than 64 !");
#endif
  //===========================================================
  // Create first MemoryBlock.
  m_get_area_block_node = m_put_area_block_node = MemoryBlock::create(block_size);
  char* const start = m_get_area_block_node->block_start();
  setp(start, start + block_size, PutThreadLock::wat(put_area_lock(type)));
  setg(start, start, start, GetThreadLock::wat(get_area_lock(type)));
  m_buffer_size_minus_unused_in_first_block.store(block_size, std::memory_order_relaxed);
  //===========================================================
  m_idevice = nullptr;
  m_odevice = nullptr;
}

// Calculate new block size for our output_buffer.
size_t StreamBuf::new_block_size(PutThread type) const
{
  PutThreadLock::crat put_area_rat(put_area_lock(type));
  return utils::malloc_size(get_data_size_upper_bound(put_area_rat) + sizeof(MemoryBlock)) - sizeof(MemoryBlock);
}

StreamBuf::int_type StreamBuf::overflow_a(int_type c, PutThread type)
{
  DoutEntering(dc::evio, "StreamBuf::overflow_a(" << char2str(c) << ") [" << this << ']');
#ifdef DEBUGDBSTREAMBUF
  printOn(std::cerr);
#endif
  if (c == static_cast<int_type>(EOF))
    return 0;
  std::streamsize available;
  char* cur_pptr = update_put_area(available, PutThreadLock::rat(put_area_lock(type)));
  if (available == 0)
  {
    //===========================================================
    // Create a new MemoryBlock.
    size_t block_size = new_block_size(type);
    // This can be done relaxed because m_buffer_size_minus_unused_in_first_block is only read by the Put thread ("this" thread).
    std::streamsize previous_buffer_size_minus_unused_in_first_block = m_buffer_size_minus_unused_in_first_block.fetch_add(block_size, std::memory_order_relaxed);
    if (AI_UNLIKELY(previous_buffer_size_minus_unused_in_first_block + block_size > m_max_allocated_block_size)) // Max alloc reached?
    {
      size_t max_alloc_size = utils::max_malloc_size(m_max_allocated_block_size - previous_buffer_size_minus_unused_in_first_block + sizeof(MemoryBlock));
      if (max_alloc_size < m_minimum_block_size + sizeof(MemoryBlock))
      {
        m_buffer_size_minus_unused_in_first_block.fetch_sub(block_size, std::memory_order_relaxed);
        return static_cast<int_type>(EOF);
      }
      size_t max_block_size = max_alloc_size - sizeof(MemoryBlock);
      m_buffer_size_minus_unused_in_first_block.fetch_sub(block_size - max_block_size, std::memory_order_relaxed);
      block_size = max_block_size;
    }
    MemoryBlock* new_block = MemoryBlock::create(block_size);
    char* start = new_block->block_start();
    *start = c;   // Write data before calling setp_pbump.
    // Only after the next line, get_data_size_upper_bound(PutThread) will return the correct value again.
    setp_pbump(start, start + block_size, 1, PutThreadLock::wat(put_area_lock(type)));
    m_put_area_block_node.load(std::memory_order_relaxed)->m_next = new_block;    // The Get Thread is guaranteed not to read m_put_area_block_node->m_next.
    m_put_area_block_node.store(new_block, std::memory_order_release);            // Now the Get Thread may read the previous value (and advance m_get_area_block_node to it).
    //===========================================================
  }
  else
  {
    *cur_pptr = c;
    pbump(1, PutThreadLock::wat(put_area_lock(type)));
  }
#ifdef DEBUGDBSTREAMBUF
  printOn(std::cerr);
#endif
  return 0;
}

bool streambuf::update_get_area(MemoryBlock*& get_area_block_node, char*& cur_gptr, std::streamsize& available, GetThreadLock::wat const& get_area_wat)
{
  // Get a copy of the last 'sync-ed' pptr.
  char* next_egptr = m_next_egptr.load(std::memory_order_acquire);    // Make sure all data was written to memory.
  char* start = get_area_block_node->block_start();
  char* end = start + get_area_block_node->get_size();
  // There are several possible cases:
  //
  // 1) We're in the same block as the put area.
  //
  //   |=========================================|
  //   ^        ^                    ^           ^
  //   |        |                    |           |
  // start   cur_gptr            next_egptr     end
  //
  // 2) We're not in the same block as the put area.
  //
  //   |================get=area=================|          |==============put=area===============|
  //   ^        ^                                ^                      ^
  //   |        |                                |                      |
  // start   cur_gptr                           end                 next_egptr
  //
  // 3) We're in the same block as the put area, but the buffer is empty and we need to reset to the beginning of the buffer:
  //
  //   |=========================================|
  //   ^              ^                          ^    next_egptr == nullptr
  //   |              |                          |
  // start      m_next_egptr2                   end
  //

  if (next_egptr != nullptr)            // Do we have to reset the get area to the beginning of the buffer?
    cur_gptr = gptr(get_area_wat);      // No; just store the current value of gptr in cur_gptr (case 1 and 2).
  else
  //---------------------------------------------------------------------------
  // Case 3
  //
  {
    Dout(dc::notice, "2. Setting m_last_gptr to " << (void*)start);
    m_last_gptr.store(start, std::memory_order_relaxed);        // We are going to reset gptr to start.
    m_next_egptr = start;                                       // Flush m_last_gptr before making m_next_egptr non-null.
                                                                // This must be memory_order_seq_cst.

    // Even though we JUST set m_next_egptr to start, a concurrent call to sync_egptr by the PutThread
    // might have changed m_next_egptr2 but missed the write to m_next_egptr, so we have to synchronize
    // (m_)next_egptr with the latest value of m_next_egptr2.
    char* expected_next_egptr = start;
    do
    {
      next_egptr = m_next_egptr2;                               // Must be memory_order_seq_cst.
    }
    while (!m_next_egptr.compare_exchange_strong(expected_next_egptr, next_egptr, std::memory_order_acquire));
    // The magic above guarantees that m_next_egptr will (have) pick(ed) up the last call to sync_egptr() (as opposed to skipping one).
    // Reset gptr to the beginning of the current memory block.
    cur_gptr = start;
  }
  //
  // 3) Here we reached the following situation:
  //
  //   |=========================================|
  //   ^              ^                          ^
  //   |              |                          |
  //cur_gptr      next_egptr                    end
  // start
  //
  // Where the meaning of cur_gptr rather is 'next gptr', we will use cur_gptr below to change gptr.
  // This case has now become a case 1, so we continue as normal.
  //
  //---------------------------------------------------------------------------

  char* cur_egptr = end;
  for (;;)
  {
    bool case1 = start <= next_egptr && next_egptr <= end;      // Does next_egptr fall in the current get area block?
    if (case1)
      cur_egptr = next_egptr;                                   // We will use cur_egptr below to change egptr.
    // The immediately available number of bytes in the get area (after the update below).
    available = cur_egptr - cur_gptr;

    if (available == 0 && !case1)
    {
      // This a case 2 therefore put_area_block_node != get_area_block_node and that remains the case.
      // Therefore we can read m_get_area_block_node->m_next here without the risk that it will be
      // updated concurrently by the PutThread.
      //===========================================================
      // Advance get area to next MemoryBlock.
      MemoryBlock* prev_get_area_block_node = get_area_block_node;
      get_area_block_node = get_area_block_node->m_next;
      cur_gptr = start = get_area_block_node->block_start();
      // m_buffer_size_minus_unused_in_first_block does not change.
      prev_get_area_block_node->release();
      //===========================================================
      cur_egptr = end = start + get_area_block_node->get_size();
      // Continue from the start, but note that next_egptr is guaranteed not nullptr here.
      // So this is now either case 1 or 2. However, since cur_gptr is now start, available
      // will be non-null unless next_egptr == start, in which case case1 becomes true.
      // So this jump back only happens once.
      continue;
    }
    break;
  }

  // Finally, update the get area.
  setg(start, cur_gptr, cur_egptr, get_area_wat);

  // Return true if the current egptr points to the end of the block.
  return cur_egptr == end;
}

// Get thread.
int StreamBuf::underflow_a(GetThread type)
{
  DoutEntering(dc::evio, "StreamBuf::underflow_a() [" << this << ']');
#ifdef DEBUGDBSTREAMBUF
  printOn(std::cerr);
#endif
  char* cur_gptr;
  std::streamsize available;
  update_get_area(m_get_area_block_node, cur_gptr, available, GetThreadLock::wat(get_area_lock(type)));
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
  return result;
}

// Note: a putback is not really thread-safe when the character
// that was previously read is already part of a complete message
// that is being decoded; nor will the putback alter the previous
// message when we get here (that is thread-safe, but different
// from when we were not by coincidence on the edge of a block).
//
// The only safe way to use putback is therefore to read a single
// character, decide we don't want it and put the character that
// we just read back so it can be part of the *next* message.
StreamBuf::int_type StreamBuf::pbackfail_a(int_type c, GetThread type)
{
  DoutEntering(dc::evio|continued_cf, "pbackfail(" << c << ") [" << this << ']');
#ifdef DEBUGDBSTREAMBUF
  printOn(std::cerr);
#endif
  if (c == static_cast<int_type>(EOF))
  {
#ifdef DEBUGDBSTREAMBUF
    printOn(std::cerr);
#endif
    Dout(dc::finish, "Returning 0");
    return 0;
  }
  bool gptr_at_eback;
  // Allocate a new MemoryBlock with minimal size before locking the get area,
  // anticipating that gptr() is going to be equal eback().
  size_t block_size = utils::malloc_size(m_minimum_block_size + sizeof(MemoryBlock)) - sizeof(MemoryBlock);
  MemoryBlock* get_area_block_node = MemoryBlock::create(block_size);
  {
    GetThreadLock::wat get_area_wat(get_area_lock(type));
    gptr_at_eback = gptr(get_area_wat) == eback(get_area_wat);
    // Likely because that should be the reason one call pbackfail in the first place.
    if (AI_LIKELY(gptr_at_eback))
    {
      //===========================================================
      // Prepend a new MemoryBlock with minimal size.
      char* const start = get_area_block_node->block_start();
      setg(start, start + block_size - 1, start + block_size, get_area_wat);
      get_area_block_node->m_next = m_get_area_block_node;
      m_get_area_block_node = get_area_block_node;
      //===========================================================
    }
    else
      gbump(-1, get_area_wat);
    // Relaxed because we don't need to be synchronized with anything. The only
    // requirement is that the Put Thread "eventually" sees this change so it
    // can keep track of a reasonable estimate.
    m_buffer_size_minus_unused_in_first_block.fetch_add(1, std::memory_order_relaxed);
    *gptr(get_area_wat) = c;
  }
  // Free the new MemoryBlock when it was unused.
  if (AI_UNLIKELY(!gptr_at_eback))
    get_area_block_node->release();
#ifdef DEBUGDBSTREAMBUF
  printOn(std::cerr);
#endif
  Dout(dc::finish, "Returning 0");
  return 0;
}

// Number of characters available for reading from this buffer (output_buffer).
std::streamsize StreamBuf::showmanyc_a(GetThread type)
{
  // showmanyc() is not supported because I don't think it is needed and it would cost extra CPU time to make it work.
  ASSERT(false);        // m_buffer_size_minus_unused_in_last_block isn't updated at the moment.
  GetThreadLock::crat get_area_rat(get_area_lock(type));
  return m_buffer_size_minus_unused_in_last_block - unused_in_first_block(get_area_rat);
}

//Get Thread.
std::streamsize StreamBuf::xsgetn_a(char* s, std::streamsize const n, GetThread type)
{
  DoutEntering(dc::evio|continued_cf, "StreamBuf::xsgetn_a(s, " << n << ") [" << this << "]... ");
#ifdef DEBUGDBSTREAMBUF
  printOn(std::cerr);
#endif
  std::streamsize remaining = n;
  while (remaining > 0)
  {
    char* cur_gptr;
    std::streamsize available;
    bool at_end = update_get_area(m_get_area_block_node, cur_gptr, available, GetThreadLock::wat(get_area_lock(type)));
    ASSERT(available >= 0);
    // If at_end is true then egptr is set at the very end of the current memory block (m_get_area_block_node, which might have been changed too!)
    std::streamsize len;
    if (available != 0)
    {
      len = std::min(available, remaining);
      std::memcpy(s, cur_gptr, len);
      gbump(len, GetThreadLock::wat(get_area_lock(type)));
      s += len;
      available -= len;
      remaining -= len;
    }
    if (!at_end)                // Leave if egptr != block end.
    {
      if (available == 0)       // Buffer empty?
PRAGMA_DIAGNOSTIC_PUSH_IGNORE_maybe_uninitialized
        store_last_gptr(cur_gptr + len);                // Sorry compiler, but if available == 0 then len is definitely defined.
PRAGMA_DIAGNOSTIC_POP
      break;
    }
    if (available == 0 &&       // gptr == egptr == block end?
        m_put_area_block_node.load(std::memory_order_acquire) != m_get_area_block_node)
    {
      // If at the moment of the load() m_put_area_block_node was already unequal m_get_area_block_node
      // then that remains the case. Therefore we now can read m_get_area_block_node->m_next.
      //===========================================================
      // Advance get area to next MemoryBlock.
      MemoryBlock* get_area_block_node = m_get_area_block_node;
      m_get_area_block_node = m_get_area_block_node->m_next;
      char* start = m_get_area_block_node->block_start();
      setg(start, start, start, get_area_lock(type));
      get_area_block_node->release();
      //===========================================================
    }
  }
  Dout(dc::finish, " = " << (n - remaining));
#ifdef DEBUGDBSTREAMBUF
  printOn(std::cerr);
#endif
  m_buffer_size_minus_unused_in_first_block -= n - remaining;
  return n - remaining;
}

char* streambuf::update_put_area(std::streamsize& available, PutThreadLock::rat const&)
{
  char* block_start = std::streambuf::pbase();
  char* cur_pptr = std::streambuf::pptr();
  if (cur_pptr != block_start &&                // Don't start a reset cycle when pptr is already at the start of the block ;).
      m_next_egptr.load(std::memory_order_acquire) != nullptr &&        // If next_egptr is nullptr then the put area was reset, but the get area wasn't yet;
                                                                        // don't reset again until it was. This read must be acquire to make sure the write
                                                                        // to last_gptr is visible too.
      cur_pptr == m_last_gptr.load(std::memory_order_relaxed))          // If this happens while next_egptr != nullptr then the buffer is truely empty (gptr == pptr).
  {
    m_next_egptr2.store(block_start, std::memory_order_relaxed);        // Initialize next_egptr2 that the GetThread will use once it resets itself.
                                                                        // This value will not be read by the GetThread until after it sees next_egptr to be nullptr.
                                                                        // Therefore this write can be relaxed.
    // A value of nullptr means 'block_start', but will prevent the PutThread to write to it
    // until the GetThread did reset too. Nor will the PutThread reset again until that happened.
    m_next_egptr.store(nullptr, std::memory_order_release);             // Atomically signal the GetThread that it must reset.
                                                                        // This write must be release to flush the write of m_next_egptr2.
    std::streambuf::pbump(block_start - cur_pptr);                      // Reset ourselves.
    cur_pptr = block_start;
  }
  available = std::streambuf::epptr() - cur_pptr;
  return cur_pptr;
}

// Write thread.
std::streamsize StreamBuf::xsputn_a(char const* s, std::streamsize const n, PutThread type)
{
  DoutEntering(dc::evio|continued_cf, "StreamBuf::xsputn_a(\"" << buf2str(s, n) << "\", " << n << ") [" << this << ']');
#ifdef DEBUGDBSTREAMBUF
  printOn(std::cerr);
#endif
  std::streamsize remaining = n;
  while (remaining > 0)
  {
    std::streamsize available;
    char* cur_pptr = update_put_area(available, PutThreadLock::rat(put_area_lock(type)));
    if (available > 0)
    {
      std::streamsize len = std::min(available, remaining);
      std::memcpy(cur_pptr, s, len);            // Write to buffer before calling pbump.
      pbump(len, PutThreadLock::wat(put_area_lock(type)));
      s += len;
      remaining -= len;
    }
    if (remaining > 0)                          // pptr == epptr (block end) AND we still need to write more?
    {
      //===========================================================
      // Create a new MemoryBlock.
      size_t block_size = new_block_size(type);
      // This can be done relaxed because m_buffer_size_minus_unused_in_first_block is only read by the Put thread ("this" thread).
      std::streamsize previous_buffer_size_minus_unused_in_first_block = m_buffer_size_minus_unused_in_first_block.fetch_add(block_size, std::memory_order_relaxed);
      if (AI_UNLIKELY(previous_buffer_size_minus_unused_in_first_block + block_size > m_max_allocated_block_size)) // Max alloc reached?
      {
        size_t max_alloc_size = utils::max_malloc_size(m_max_allocated_block_size - previous_buffer_size_minus_unused_in_first_block + sizeof(MemoryBlock));
        if (max_alloc_size < m_minimum_block_size + sizeof(MemoryBlock))
        {
          m_buffer_size_minus_unused_in_first_block.fetch_sub(block_size, std::memory_order_relaxed);
          return static_cast<int_type>(EOF);
        }
        size_t max_block_size = max_alloc_size - sizeof(MemoryBlock);
        m_buffer_size_minus_unused_in_first_block.fetch_sub(block_size - max_block_size, std::memory_order_relaxed);
        block_size = max_block_size;
      }
      MemoryBlock* new_block = MemoryBlock::create(block_size);
      char* start = new_block->block_start();
      // Only after the next line, get_data_size_upper_bound(PutThread) will return the correct value again.
      setp(start, start + block_size, PutThreadLock::wat(put_area_lock(type)));
      m_put_area_block_node.load(std::memory_order_relaxed)->m_next = new_block;    // The Get Thread is guaranteed not to read m_put_area_block_node->m_next.
      m_put_area_block_node.store(new_block, std::memory_order_release);            // Now the Get Thread may read the previous value (and advance m_get_area_block_node to it).
      //===========================================================
    }
  }
  Dout(dc::finish, " = " << (n - remaining));
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

std::streamsize streambuf::showmanyc()
{
  GetThread type;
  return static_cast<StreamBuf*>(m_input_streambuf)->showmanyc_a(type);
}

std::streambuf::int_type streambuf::underflow()
{
  GetThread type;
  return static_cast<StreamBuf*>(m_input_streambuf)->underflow_a(type);
}

std::streambuf::int_type streambuf::pbackfail(int_type c)
{
  GetThread type;
  return static_cast<StreamBuf*>(m_input_streambuf)->pbackfail_a(c, type);
}

std::streamsize streambuf::xsgetn(char* s, std::streamsize n)
{
  GetThread type;
  return static_cast<StreamBuf*>(m_input_streambuf)->xsgetn_a(s, n, type);
}

std::streambuf::int_type streambuf::overflow(int_type c)
{
  PutThread type;
  return static_cast<StreamBuf*>(this)->overflow_a(c, type);
}

std::streamsize streambuf::xsputn(char const* s, std::streamsize n)
{
  PutThread type;
  return static_cast<StreamBuf*>(this)->xsputn_a(s, n, type);
}

//============================================================================

void StreamBuf::reduce_buffer(GetThreadLock::wat const& get_area_wat, PutThreadLock::wat const& put_area_wat)
{
  // The buffer if empty, so there is only one block (get_area_block_node == put_area_block_node).
  if (m_get_area_block_node->get_size() > m_minimum_block_size)
  {
    //===========================================================
    // Replace first and only MemoryBlock.
    MemoryBlock* get_area_block_node = m_get_area_block_node;
    m_get_area_block_node = MemoryBlock::create(m_minimum_block_size);
    m_buffer_size_minus_unused_in_first_block.store(m_minimum_block_size, std::memory_order_relaxed);
    m_put_area_block_node.store(m_get_area_block_node, std::memory_order_release);
    get_area_block_node->release();
    //===========================================================
  }
  // Reset the empty buffer.
  char* start = m_get_area_block_node->block_start();
  setg(start, start, start, get_area_wat);
  setp(start, start + m_minimum_block_size, put_area_wat);
}

int Buf2Dev::sync()
{
  // m_odevice points to the device whose constructor this buffer was passed to.
  return m_odevice->sync();
}

// Read thread of linked device.
void Buf2Dev::flush()
{
  // m_odevice points to the device whose constructor this buffer was passed to.
  PutThread type;
  m_odevice->restart_if_non_active(type);
}

// Read thread of linked device.
void LinkBuffer::flush()
{
  // m_odevice points to the device whose constructor this buffer was passed to.
  PutThread type;
  m_odevice->restart_if_non_active(type);
}

bool StreamBuf::release(FileDescriptor const* DEBUG_ONLY(device))
{
  // StreamBuf should always be used as base class of InputBuffer, OutputBuffer or LinkBuffer only.
  ASSERT(m_device_counter > 0);
  if (--m_device_counter == 0)
  {
    delete this;
    return true;
  }
  else
  {
    // When m_device_counter becomes 2, the ref count of m_odevice is increased.
    // It should never be deleted before the input device!
    ASSERT(device == m_idevice);
    // Resetting the device pointer is necessary because of `sync' and `flush'.
    m_idevice = nullptr;

#ifdef CWDEBUG
    m_odevice->inhibit_deletion();      // Allow Debug output below to still use this object.
    int count =
#endif
    m_odevice->allow_deletion();

    Dout(dc::io, "this = " << this << "; Calling StreamBuf::release(" << (void*)device << "), " <<
        m_device_counter << " output device left: " << m_odevice <<
        "; decrementing ref count of that device (now " << (count - 2) << ").");

#ifdef CWDEBUG
    m_odevice->allow_deletion();
#endif

    return false;
  }
}

void StreamBuf::set_input_device(InputDevice* device)
{
  // Don't pass a StreamBuf to more than one device.
  // Also note set_input_device should only be called from InputDevice::input, don't call it directly.
  ASSERT(!m_idevice);
  if (++m_device_counter == 2)
  {
    CWDEBUG_ONLY(int count =) m_odevice->inhibit_deletion();
    Dout(dc::io, "this = " << this << "; Calling StreamBuf::set_input_device(" << device <<
        "); incremented ref count of output device [" << m_odevice << "] (now " << (count + 1) << ").");
  }
  m_idevice = device;
}

void StreamBuf::set_output_device(OutputDevice* device)
{
  // Don't pass a StreamBuf to more than one device.
  // Also note set_output_device should only be called from the constructor of OutputBuffer or LinkBuffer. Don't call it directly.
  ASSERT(!m_odevice);
  if (++m_device_counter == 2)
  {
    CWDEBUG_ONLY(int count =) device->inhibit_deletion();
    Dout(dc::io, "this = " << this << "; Calling StreamBuf::set_output_device(" << device <<
        "); incremented ref count of output device [" << device << "] (now " << (count + 1) << ").");
  }
  m_odevice = device;
}

#ifdef CWDEBUG
void StreamBuf::printOn(std::ostream& os) const
{
  os << "----------------------------------------------------------------------" << std::endl;
  os << "minimum_block_size = " << m_minimum_block_size << "; "
        "buffer_full_watermark = " << m_buffer_full_watermark << "; "
        "max_allocated_block_size = " << m_max_allocated_block_size;
  int current_number_of_blocks = 0;
  for (MemoryBlock* block_node = m_get_area_block_node; block_node; block_node = block_node->m_next)
    ++current_number_of_blocks;
  os << "; current_number_of_blocks = " << current_number_of_blocks << std::endl;
  os << "Block nodes: " << std::endl;
  unsigned int block_count = 0;
  size_t total_size = 0;
  os << "Start\t\tSize\n";
  for (MemoryBlock* block_node = m_get_area_block_node; block_node; block_node = block_node->m_next)
  {
    os << (void*)block_node->block_start() << '\t' << block_node->get_size() << std::endl;
    total_size += block_node->get_size();
    ++block_count;
  }
  os << "Total size: " << total_size << std::endl;
//  if (total_size != output_buffer.get_total_block_size())
//    DoutFatal(dc::core, "Inconsistent total allocated size!");
  // Get a get- and put- area snapshot.
  GetThread get_type;
  PutThread put_type;
  char* cur_eback;
  char* cur_gptr;
  char* cur_egptr;
  char* cur_pbase;
  char* cur_pptr;
  char* cur_epptr;
  {
    GetThreadLock::crat get_area_rat(get_area_lock(get_type));
    PutThreadLock::crat put_area_rat(put_area_lock(put_type));
    cur_eback = eback(get_area_rat);
    cur_gptr = gptr(get_area_rat);
    cur_egptr = egptr(get_area_rat);
    cur_pbase = pbase(put_area_rat);
    cur_pptr = pptr(put_area_rat);
    cur_epptr = epptr(put_area_rat);
  }
  MemoryBlock* put_area_block_node = m_put_area_block_node.load();
  os << "get_area_block_node = " << (void*)m_get_area_block_node;
  os << "; put_area_block_node = " << (void*)put_area_block_node << std::endl;
  os << "get area: " << (void*)cur_eback << " - " << (void*)cur_gptr << "(" << cur_gptr - cur_eback << ")" <<
    " - " << (void*)cur_egptr << "(" << cur_egptr - cur_eback << ")";
#if CWDEBUG_ALLOC
  os << "\t[ " << find_alloc(cur_eback)->start() << " (" << find_alloc(cur_eback)->size() << ") ]";
#endif
  os << std::endl;
  os << "put area: " << (void*)cur_pbase << " - " << (void*)cur_pptr << "(" << cur_pptr - cur_pbase << ")" <<
    " - " << (void*)cur_epptr << "(" << cur_epptr - cur_pbase << ")";
#if CWDEBUG_ALLOC
  os << "\t[ " << find_alloc(cur_pbase)->start() << " (" << find_alloc(cur_pbase)->size() << ") ]";
#endif
  os << std::endl;
#if CWDEBUG_ALLOC
  if ((char*)find_alloc(cur_eback)->start() + sizeof(MemoryBlock) != cur_eback)
    DoutFatal(dc::core, "get area points to non-allocated block !");
  if (cur_gptr != cur_eback && (char*)find_alloc(cur_gptr - 1)->start() + sizeof(MemoryBlock) != cur_eback)
    DoutFatal(dc::core, "get area get pointer points outside allocated block !");
  if (cur_egptr != cur_eback && (char*)find_alloc(cur_egptr - 1)->start() + sizeof(MemoryBlock) != cur_eback)
    DoutFatal(dc::core, "end of get area points outside allocated block !");
  if ((char*)find_alloc(cur_pbase)->start() + sizeof(MemoryBlock) != cur_pbase)
    DoutFatal(dc::core, "put area points to non-allocated block !");
  if (cur_pptr != cur_pbase && (char*)find_alloc(cur_pptr - 1)->start() + sizeof(MemoryBlock) != cur_pbase)
    DoutFatal(dc::core, "put area put pointer points outside allocated block !");
  if (cur_epptr != cur_pbase && (char*)find_alloc(cur_epptr - 1)->start() + sizeof(MemoryBlock) != cur_pbase)
    DoutFatal(dc::core, "end of put area points outside allocated block !");
#endif
  os << "Total string length: " << total_size - (cur_gptr - cur_eback) - (cur_epptr - cur_pptr) << std::endl;
  for (MemoryBlock* block_node = m_get_area_block_node; block_node; block_node = block_node->m_next)
  {
    os << "[" << (void*)block_node << "] ";
    if (block_node == m_get_area_block_node && block_node == put_area_block_node)
    {
      if (cur_pptr >= cur_gptr)
        os << "\"" << buf2str(cur_gptr, cur_pptr - cur_gptr) << "\"" << std::endl;     // Print from gptr() to pptr().
      else if (is_resetting())
        os << "\"" << buf2str(block_node->block_start(), cur_pptr - cur_pbase) << "\" (resetting)" << std::endl;     // Print from start of buffer to pptr().
      else
        os << "INVALID RANGE" << std::endl;
    }
    else if (block_node == m_get_area_block_node)
      os << "\"" << buf2str(cur_gptr, block_node->get_size() - (cur_gptr - cur_eback)) << std::endl;      // Print from igptr() to the end of the buffer.
    else if (block_node == put_area_block_node)
      os << buf2str(block_node->block_start(), cur_pptr - cur_pbase) << "\"" << std::endl;   // Print from start of buffer to pptr().
    else
      os << buf2str(block_node->block_start(), block_node->get_size()) << std::endl;         // Print the whole buffer.
  }
  if (cur_eback != m_get_area_block_node->block_start() ||
      cur_pbase != put_area_block_node->block_start() ||
      cur_epptr != cur_pbase + put_area_block_node->get_size() ||
      (m_get_area_block_node == put_area_block_node && !is_resetting() && cur_egptr > cur_pptr) ||
      cur_egptr > cur_eback + m_get_area_block_node->get_size() ||
      cur_gptr < cur_eback || cur_gptr > cur_egptr ||
      cur_pptr < cur_pbase || cur_pptr > cur_epptr)
    DoutFatal(dc::core, "Pointers inconsistent");
  os << "----------------------------------------------------------------------" << std::endl;
}
#endif

} // namespace evio
