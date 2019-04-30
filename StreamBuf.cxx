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
#ifdef DEBUGDBSTREAMBUF
  printOn(std::cerr);
#endif
  return 0;
}

// Get thread.
int StreamBuf::underflow_a(GetThread type)
{
  DoutEntering(dc::evio, "StreamBuf::underflow_a() [" << this << ']');
#ifdef DEBUGDBSTREAMBUF
  printOn(std::cerr);
#endif
  int result = 0;
  while (1)
  {
    GetThreadLock::wat get_area_wat(get_area_lock(type));
    // True if egptr points to the end of m_get_area_block_node after returning from this function.
    bool reached_end = sync_next_egptr(m_get_area_block_node, get_area_wat);
    if (gptr(get_area_wat) == egptr(get_area_wat))
    {
      if (reached_end &&
          m_put_area_block_node.load(std::memory_order_acquire) != m_get_area_block_node)
      {
        // If at the moment of the load() m_put_area_block_node was already unequal m_get_area_block_node
        // then that remains the case. Therefore we now can read m_get_area_block_node->m_next.
        //===========================================================
        // Advance get area to next MemoryBlock.
        MemoryBlock* get_area_block_node = m_get_area_block_node;
        m_get_area_block_node = m_get_area_block_node->m_next;
        char* start = m_get_area_block_node->block_start();
        setg(start, start, start, get_area_wat);
        // m_buffer_size_minus_unused_in_first_block does not change.
        get_area_block_node->release();
        continue;
        //===========================================================
      }
      // There is nothing to read anymore at the moment.
      Dout(dc::evio, "Returning EOF");
      // FIXME: Reduce the buffer? See remark in OutputDevice::VT_impl::write_to_fd.
      result = EOF;
    }
    break;
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
    bool reached_end;
    char* cur_gptr;
    std::streamsize available;
    {
      GetThreadLock::wat get_area_wat(get_area_lock(type));
      reached_end = sync_next_egptr(m_get_area_block_node, get_area_wat);
      cur_gptr = gptr(get_area_wat);
      available = egptr(get_area_wat) - cur_gptr;
    }
    std::streamsize len;
    if (available > 0)
    {
      len = std::min(available, remaining);
      std::memcpy(s, cur_gptr, len);
      gbump(len, GetThreadLock::wat(get_area_lock(type)));
      s += len;
      remaining -= len;
    }
    if (!reached_end)           // Leave if egptr != block end.
      break;
    if (available == len &&     // gptr == egptr == block end?
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
    char* cur_pptr;
    {
      PutThreadLock::rat put_area_rat(put_area_lock(type));
      cur_pptr = pptr(put_area_rat);
      available = epptr(put_area_rat) - cur_pptr;
    }
    std::streamsize len;
    if (available > 0)
    {
      len = std::min(available, remaining);
      std::memcpy(cur_pptr, s, len);            // Write to buffer before calling pbump.
      pbump(len, PutThreadLock::wat(put_area_lock(type)));
      s += len;
      remaining -= len;
    }
    if (remaining > 0)                          // pptr == epptr == block end AND we still need to write more?
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
  // Reset the empty the buffer.
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
    DEBUG_ONLY(int count =) m_odevice->inhibit_deletion();
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
    DEBUG_ONLY(int count =) device->inhibit_deletion();
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
      os << "\"" << buf2str(cur_gptr, cur_pptr - cur_gptr) << "\"" << std::endl;     // Print from gptr() to pptr().
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
      (m_get_area_block_node == put_area_block_node && cur_egptr > cur_pptr) ||
      cur_egptr > cur_eback + m_get_area_block_node->get_size() ||
      cur_gptr < cur_eback || cur_gptr > cur_egptr ||
      cur_pptr < cur_pbase || cur_pptr > cur_epptr)
    DoutFatal(dc::core, "Pointers inconsistent");
  os << "----------------------------------------------------------------------" << std::endl;
}
#endif

} // namespace evio
