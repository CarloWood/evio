// evio -- Event Driven I/O support.
//
//! @file
//! @brief Declaration of namespace evio; class MemoryBlocksBuffer, MsgBlock, StreamBuf, InputBuffer, OutputBuffer and LinkBuffer.
//
// Copyright (C) 2018 Carlo Wood.
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

#pragma once

#include "sys.h"
#include "debug.h"
#include "utils/log2.h"
#include "utils/malloc_size.h"
#include "utils/is_power_of_two.h"
#include "utils/nearest_power_of_two.h"
#include <atomic>
#include <mutex>

#if defined(CWDEBUG) && !defined(DOXYGEN)
NAMESPACE_DEBUG_CHANNELS_START
extern channel_ct io;           // IO specific debug output.
NAMESPACE_DEBUG_CHANNELS_END
#endif

namespace evio {

// Forward declarations.
class FileDescriptor;
class InputDevice;
class OutputDevice;
class MsgBlock;
class StreamBuf;

// The memory overhead of a call to malloc() in bytes.
//
// Determined during configuration. When N bytes are allocated with malloc(N) then in
// reality N + malloc_overhead_c bytes are used.
static constexpr size_t malloc_overhead_c = CW_MALLOC_OVERHEAD;

//=============================================================================
//
// class MemoryBlock
//
// A reference counted memory block.
//
// The object is put at the beginning of a large(r) dynamically allocated
// memory block.
//
// A MemoryBlock* points to a single contiguous memory block allocated with
// malloc, where at the top a MemoryBlock object was created with placement new.
//
//                                             Allocated size with malloc().
//                   ___________________      /
// MemoryBlock* --> |                   |  ^  ^  ^  sizeof MemoryBlock.
//                  |   A MemoryBlock   |  |  |  |__/
//                  |                   |  |  |  v
//                  +-------------------+  |  |---
// block_start() -> |                   |  |  |  ^  m_block_size.
//                  |         ^         |  |  |  |__/
//                  |         |         |  |  |  |
//                  |     char data     |  |  |  |
//                  |         |         |  |  |  |
//                  |         v         |  |  |  |
//                  |                   |  |  |  |
//                  |___________________|  |  v  v
//                  | malloc_overhead_c |  |  \  \__ block_size
//                  |___________________|  v   \____ alloc_size
//                                          \_______ heap_size
//
// We want the data block to aligned as size_t, so sizeof(MemoryBlock) is
// a multiple of sizeof(size_t).

class MemoryBlock
{
  friend class MsgBlock;                // Needs access to create/add_reference/release.
  friend class MemoryBlocksBuffer;      // Needs access to create/release.
  friend class InputDevice;             // Needs access to create/release.

 private:
  mutable std::atomic<int> m_count;     // Reference counter.
  size_t const m_block_size;            // Size of buffer area of this block in bytes.
  std::atomic<MemoryBlock*> m_next;     // The next block in the list, or nullptr if this was the last.

  MemoryBlock(size_t block_size) : m_count(1), m_block_size(block_size), m_next(nullptr) { }
  MemoryBlock(MemoryBlock const&) = delete;
  MemoryBlock& operator=(MemoryBlock const&) = delete;

  // Create a new memory block with a reference count of 1 and a block size of block_size.
  // This initial pointer is stored in the MemoryBlocksBuffer that this MemoryBlock belongs to.
  // The returned MemoryBlock can be viewed as a list containing a single block.
  static MemoryBlock* create(size_t block_size)
  {
    // The caller is responsible to make this work.
    ASSERT(utils::is_power_of_two(sizeof(MemoryBlock) + block_size + malloc_overhead_c) ||
           (sizeof(MemoryBlock) + block_size + malloc_overhead_c) % 4096 == 0);
    // No mutex locking is required while creating a new memory block.
    MemoryBlock* memory_block = (MemoryBlock*)malloc(sizeof(MemoryBlock) + block_size);
    AllocTag1(memory_block);
    new (memory_block) MemoryBlock(block_size);
    return memory_block;
  }

  // Increment reference count by one. Called for every MsgBlock object that is created.
  void add_reference() const
  {
    m_count.fetch_add(1, std::memory_order_relaxed);
  }

  // Decrement reference count by one. Called when a MsgBlock is destructed and/or when
  // this MemoryBlock is removed from its MemoryBlocksBuffer.
  void release() const
  {
    if (m_count.fetch_sub(1, std::memory_order_release) == 1)
    {
      std::atomic_thread_fence(std::memory_order_acquire);
      // The object should be delinked before being released.
      ASSERT(m_next == nullptr);
      this->~MemoryBlock();
      free(const_cast<MemoryBlock*>(this));
    }
  }

 public:
  // Returns the start of the memory block for data.
  // Note that this function should not be called when it is possible that the BRT resets the get/put area of an empty buffer.
  char* block_start() const { return const_cast<char*>(reinterpret_cast<char const*>(this) + sizeof(MemoryBlock)); }

  // Returns the current size of the allocated memory block.
  size_t get_size() const { return m_block_size; }
};

// The minimum size ever of the data block, in bytes, is
static constexpr size_t minimum_data_block_size = 64;

// The corresponding (minimum) allocated memory for that size would be
static constexpr size_t minimum_allocated_size = minimum_data_block_size + sizeof(MemoryBlock);

// But we demand that the space on the heap is a power of two, hence
static constexpr size_t minimum_heap_space = utils::nearest_power_of_two(minimum_allocated_size + malloc_overhead_c);

// The smallest value passed to malloc() is therefore,
static constexpr size_t minimum_malloc_size = minimum_heap_space - malloc_overhead_c;

// m_block_size should be the last member in the object, so that
static_assert(alignof(MemoryBlock) == alignof(size_t) && sizeof(MemoryBlock) % sizeof(size_t) == 0, "Unexpected alignment of the data block part.");

class mystreambuf : private std::streambuf
{
  friend class MemoryBlocksBuffer;

 public:
  using int_type = std::streambuf::int_type;
  mystreambuf();

 private:
  auto eback() const { return std::streambuf::eback(); }
  auto gptr() const { return std::streambuf::gptr(); }
  auto egptr() const { return std::streambuf::egptr(); }

  auto pbase() const { return std::streambuf::pbase(); }
  auto pptr() const { return std::streambuf::pptr(); }
  auto epptr() const { return std::streambuf::epptr(); }

  void gbump(int n) { std::streambuf::gbump(n); }
  void setg(char* eb, char* g, char* eg) { std::streambuf::setg(eb, g, eg); }
  void pbump(int n) { std::streambuf::pbump(n); }
  void setp(char* p, char* ep) { std::streambuf::setp(p, ep); }

 public:
  std::streambuf* get_sb() { return static_cast<std::streambuf*>(this); }
};

//=============================================================================
//
// class MemoryBlocksBuffer
//
// This class represents a singly linked list of MemoryBlocks.
//
// It keeps track of the total size of the buffer as the sum
// of the block sizes of all its MemoryBlocks. When a new block
// is appended, the size of that block is made equal to the
// current buffer size (so the size is more or less doubled)
// but rounding the required heap space off to the nearest
// efficient value as determined by utils::malloc_size.

class MemoryBlocksBuffer
{
 private:
  size_t const m_max_alloc;             // Maximum allowed number of allocated bytes.
  std::mutex m_mutex;
  size_t m_total_block_size;            // Total amount of available memory in the buffer.
  size_t m_total_data_written;          // The number of bytes written to the buffer.
  size_t m_total_data_read;             // The number of bytes read from the buffer.
  MemoryBlock* m_get_area;              // Pointer to the first MemoryBlock (the front).
  MemoryBlock* m_put_area;              // Pointer to the last MemoryBlock (the back).

 public:
  // Constructor, sets a maximum buffer size.
  MemoryBlocksBuffer(size_t max_alloc) : m_max_alloc(max_alloc), m_total_block_size(0), m_total_data_written(0), m_total_data_read(0), m_get_area(nullptr), m_put_area(nullptr) { }
  MemoryBlocksBuffer(MemoryBlocksBuffer const&) = delete;
  MemoryBlocksBuffer& operator=(MemoryBlocksBuffer const&) = delete;

  ~MemoryBlocksBuffer()
  {
    // Release all remaining memory blocks.
    while (m_get_area)
      brt_pop_front();
  }

  //---------------------------------------------------------------------------
  // Public accessors:
  //

#ifdef CWDEBUG
  // Accessor for m_max_alloc.
  size_t get_max_alloc() const { return m_max_alloc; }

  // Accessor that returns the total number of allocated bytes.
  size_t get_total_block_size() const { return m_total_block_size; }
#endif

  //---------------------------------------------------------------------------
  // Manipulator methods.
  //

  auto eback(mystreambuf const* self) const { return self->eback(); }
  auto gptr(mystreambuf const* self) const { return self->gptr(); }
  auto egptr(mystreambuf const* self) const { return self->egptr(); }

  auto pbase(mystreambuf const* self) const { return self->pbase(); }
  auto pptr(mystreambuf const* self) const { return self->pptr(); }
  auto epptr(mystreambuf const* self) const { return self->epptr(); }

  void gbump(int n, mystreambuf* self) { self->gbump(n); }
  void setg(char* eb, char* g, char* eg, mystreambuf* self) { self->setg(eb, g, eg); }
  void pbump(int n, mystreambuf* self) { self->pbump(n); }
  void setp(char* p, char* ep, mystreambuf* self) { self->setp(p, ep); }

  // Add a new block to the end of the list.
  // This function may only be called by the Buffer Write Thread (BWT).
  bool bwt_push_back(size_t minimum_block_size)
  {
    // Calculate the size of the next block.
    size_t total_data_size = m_total_data_written - m_total_data_read;
    size_t block_size = utils::malloc_size(std::max(minimum_block_size, total_data_size) + sizeof(MemoryBlock)) - sizeof(MemoryBlock);
    bool buffer_full;
    {
      std::lock_guard<std::mutex> lock(m_mutex);
      buffer_full = m_total_block_size + block_size > m_max_alloc;
    }
    // By releasing the lock, buffer_full becomes fuzzy (it becomes 'buffer_recently_full') - but that is OK.
    // Note that the only transition possible is from true to false, so we'll never allocate too much memory anyway.
    if (!buffer_full)
    {
      MemoryBlock* new_block = MemoryBlock::create(block_size);
      std::lock_guard<std::mutex> lock(m_mutex);
      m_total_block_size += block_size;
      m_put_area->m_next = new_block;
      m_put_area = new_block;
      return true;
    }
    return false;
  }

  // Remove the first MemoryBlock from the list.
  // This function may only be called by the Buffer Read Thread (BRT).
  void brt_pop_front()
  {
    MemoryBlock* memory_block = m_get_area;
    // Do not call brt_pop_front() on an empty list. This assures that
    // while we're here the BWT won't be accessing m_list concurrently.
    ASSERT(memory_block);
    // Delink the block.
    m_get_area = memory_block->m_next;
    m_total_block_size -= memory_block->get_size();
    memory_block->release();
  }

  void reduce_single_block_size(size_t new_size)
  {
    MemoryBlock* memory_block = m_get_area;
    ASSERT(memory_block && memory_block == m_put_area); // Exactly one block.
    m_total_block_size -= memory_block->get_size() - new_size;
    m_get_area = m_put_area = MemoryBlock::create(new_size);
    memory_block->release();
  }
};

//=============================================================================
//
// class MsgBlock
//
// MsgBlock is only passes as a temporary object to InputDevice::decode and as such
// a particular instance is only used by the BRT (Buffer Reading Thread) which means
// it is effectively single threaded with respect to the whole MemoryBlocksBuffer.
//
class MsgBlock
{
 private:
  char const* m_start;
  size_t m_size;
  MemoryBlock const* m_memory_block;

 public:
  MsgBlock(char const* start, size_t size, MemoryBlock const* memory_block) : m_start(start), m_size(size), m_memory_block(memory_block)
  {
    ASSERT(m_start >= m_memory_block->block_start() && m_start + m_size <= m_memory_block->block_start() + m_memory_block->get_size());
    m_memory_block->add_reference();
  }

  ~MsgBlock() { m_memory_block->release(); }

  MsgBlock(MsgBlock const& msg_block) : m_start(msg_block.m_start), m_size(msg_block.m_size), m_memory_block(msg_block.m_memory_block)
  {
    m_memory_block->add_reference();
  }

  MsgBlock& operator=(MsgBlock const& msg_block)
  {
    if (this == &msg_block)
      return *this;
    m_memory_block->release();
    m_start = msg_block.m_start;
    m_size = msg_block.m_size;
    m_memory_block = msg_block.m_memory_block;
    ASSERT(m_start >= m_memory_block->block_start() && m_start + m_size <= m_memory_block->block_start() + m_memory_block->get_size());
    m_memory_block->add_reference();
    return *this;
  }

  char const* get_start() const { return m_start; }
  size_t get_size() const { return m_size; }
};

//=============================================================================
//
// class StreamBuf
//
// Dynamic Blocks STREAM BUFfer
//
// SYNOPSIS
//
// List of allocated blocks for the streambufs put area.
// Therefore, this list is associated with output (ostream).
// The get area of the streambuf that this object is associated
// with will get from 'our input buffer' which is another `StreamBuf'
// object pointed to by attribute `input_streambuf'.
//
// Starting with one empty block in the put area of `streambuf', with a
// user definable minimum size, and an external get area, new blocks are
// allocated when needed and old blocks are freed when empty. The size of
// the newly allocated blocks depends on the current total number of valid
// bytes buffered.
// The primary goal of this buffer is to be fast: Data is never moved.
//
// NOTE:
// The reason for this seemingly complex 'crosslinked' interface is that
// this way all functional different code only exists once and is therefore
// better maintainable. However, if maintenance is needed you will have to
// understand it nevertheless :). To still be able to understand this, do
// the following magic trick: Assume that the input and output buffer are
// the same buffer, which gives you only one streambuf interface. Make that
// work and then replace all input related streambuf calls by the same calls
// prepended with the character 'i'. This means: eback() becomes ieback(),
// gptr() becomes igptr() etc.
//

class StreamBuf : public std::streambuf
{
 public:
  //---------------------------------------------------------------------------
  // Constructor
  //

  // Construct a `StreamBuf' object. The minimum number of allocated
  // bytes for one block of the output buffer is `minimum_blocksize'.
  // The maximum possible number of total allocated bytes of all blocks
  // together is max_alloc. When this value is reached, `overflow' will
  // return EOF.
  // The method `buffer_full' returns true when the number of buffered
  // bytes in the output buffer exceed `buffer_full_watermark'.
  // After using this constructor, the input buffer is the same as the
  // output buffer. Use `set_input_buffer' to change this.
  StreamBuf(size_t minimum_blocksize, size_t buffer_full_watermark, size_t max_alloc);

 public:
  //---------------------------------------------------------------------------
  // Public initializers
  //

  void set_input_buffer(StreamBuf* b);

 public:
  //---------------------------------------------------------------------------
  // Public accessors
  //

  // Returns the logarithm base 2 of minimum block size.
  // *undocumented*
  unsigned short get_log2_min_buf_size() const { return log2_min_buf_size; }

  // Returns the minimum block size in bytes.
  size_t minimum_block_size() const { return (1 << log2_min_buf_size) - malloc_overhead_c - sizeof(MemoryBlock); }

  // Returns `true' when this buffer currently has more then one block
  // allocated. This can be used to speed up read/write access methods.
  bool has_multiple_blocks() const { return get_area_block_node != put_area_block_node; }

  // Return the number of unused bytes in the get area of the input buffer
  // *undocumented*
  size_t unused_in_first_block() const { return gptr() - eback(); }

  // Return the number of unused bytes in the put area of the output buffer.
  // *undocumented*
  size_t unused_in_last_block() const { return epptr() - pptr(); }

  // Return the current number of valid bytes in the output buffer.
  //
  // Note: This assumes that the get area is the first block and the
  // put area is the last block.  This might change when pubseek() is added.
  size_t used_size() const
  {
    return output_buffer.get_total_block_size() -
        object_getting_from_my_buffer->unused_in_first_block() -
        unused_in_last_block();
  }

  // Return the maximum allowed amount of allocated bytes for this buffer.
  size_t get_max_alloc() const { return output_buffer.get_max_alloc(); }

  // Update the get area to include the most recently written data,
  // then return the amount of contiguous bytes in the get area.
  // This might return 0 even if the buffer isn't empty, therefore call
  // force_next_contiguous_number_of_bytes() when it returns 0.
  size_t next_contiguous_number_of_bytes() { return ishowmanyc(); }

  // Returns true if a string with length `len' is contiguous
  // in the current get area of the output buffer.
  bool is_contiguous(size_t len) const;

  // Calculate the size of the new block as a function of the currently
  // amount of buffered data.  The new size is adjusted for gnu malloc,
  // which doesn't hurt when you use another malloc.
  // *undocumented*
  size_t new_block_size() const;

  // Returns true if the output buffer is full.
  bool buffer_full() const
  {
    bool full = used_size() >= max_used_size;
#ifdef CWDEBUG
    if (full)
      Dout(dc::warning, "StreamBuf::buffer_full: used_size() = " << used_size() << " >= max_used_size = " << max_used_size << " [" << this << ']');
#endif
    return full;
  }

  // Returns true if output buffer is empty.
  bool buffer_empty() const { return igptr() == pptr(); }

#ifdef CWDEBUG
  // Print debug information in stream `o'.
  // *undocumented*
  void printOn(std::ostream& o) const;
#endif

  // Undocumented (use outside of libcw is depricated)
  MemoryBlock* get_get_area_block_node() const { return get_area_block_node; }
  MemoryBlock* get_put_area_block_node() const { return put_area_block_node; }

 protected:
  //---------------------------------------------------------------------------
  // Get and put area of the `other' buffer.

  // Start of input buffer
  char* ieback() const { return input_streambuf->eback(); }

  // Next character in input buffer
  char* igptr() const { return input_streambuf->gptr(); }

  // End of input buffer
  char* iegptr() const { return input_streambuf->egptr(); }

  // Return start of put area of our input buffer (called by kernel)
  char* ipbase() const { return input_streambuf->pbase(); }

  // Return next write position in put area of our input buffer
  // (called by kernel).
  char* ipptr() const { return input_streambuf->pptr(); }

  // Return end of put area of our input buffer (called by kernel)
  char* iepptr() const { return input_streambuf->epptr(); }

//=============================================================================

 protected:
  //---------------------------------------------------------------------------
  // `streambuf' interface (See ANSI C++ draft)
  //

  // Called when a block is full.
  // BWT.
  int_type overflow(int_type c = EOF) override;

  // Called when a block is empty.
  // BRT.
  int_type underflow() override { return input_streambuf->iunderflow(); }

  // Called when a putback failed. Manipulates the gptr so must be BRT.
  int_type pbackfail(int_type c) override { return input_streambuf->ipbackfail(c); }

  // Though ANSI C++, not implemented in libg++-2.7.1. Used by libcw.
  // This should return the number of contiguous characters at the
  // beginning of the get area.
  // Note: libcw demands that this function does not return '0' unless
  // the buffer is empty (this is not explicitly demanded by ANSI).
  // BRT.
  std::streamsize showmanyc() override { return input_streambuf->ishowmanyc(); }

 protected:
  //---------------------------------------------------------------------------
  // Protected manipulators that work on the get area or on the put area of the
  // input buffer. All these functions start with an 'i'.
  //

  // Advance get pointer of input buffer `n' positions.
  // BRT.
  void igbump(int n) { input_streambuf->gbump(n); }

  // (Re-)initialize the get area of the input buffer.
  void isetg(char* eb, char* g, char* eg) { input_streambuf->setg(eb, g, eg); }

  // Called by the object reading from my output buffer, reads `n'
  // number of characters into `s'.
  std::streamsize ixsgetn(char* s, std::streamsize n);

  // Called by the object reading from my output buffer,
  // This should return the number of contiguous characters at the
  // beginning of the get area of my output buffer.
  std::streamsize ishowmanyc();

  // Called by the object reading from my output buffer when a `putback' fails.
  int_type ipbackfail(int_type c);

  // Called by the object reading from my output buffer, when the
  // end of the get area is reached.
  int iunderflow();

  // Write one character `c' to my input_buffer, should only be called
  // when the put area of the input buffer is full.
  int ioverflow(int c = EOF) { return input_streambuf->overflow(c); }

  // Write `n' bytes from `s' to my input buffer.
  std::streamsize ixsputn(char const* s, std::streamsize n) { return input_streambuf->xsputn(s, n); }

  // Advance the put pointer of the input buffer `n' characters.
  void ipbump(int n) { input_streambuf->pbump(n); }

  // Set the start and end of the put area of my input buffer.
  void isetp(char* p, char* ep) { input_streambuf->setp(p, ep); }

 private:
  //---------------------------------------------------------------------------
  // Private attributes:
  //

  // 2 ^ log2_min_buf_size - malloc_overhead_c - sizeof(MemoryBlock), is minimum block size
  unsigned short log2_min_buf_size;

  // 'buffer_full' returns true when this amount is buffered.
  size_t max_used_size;

  // Pointer to the get area - block object.
  MemoryBlock* get_area_block_node;

  // Pointer to the put area - block object.
  MemoryBlock* put_area_block_node;

  // List of allocated blocks for the streambufs 'put area',
  // associating `output_buffer' with output (ostream).
  MemoryBlocksBuffer output_buffer;

  // Optional pointer to list of allocated blocks for the streambufs
  // 'get area', associating `input_streambuf' with input (istream).
  // If only one buffer is used, this should point to `this'.
  // The union symbolizes that only two objects of type `StreamBuf'
  // can be linked together, if three or more are used these should
  // be different pointers.
  union {
    StreamBuf* input_streambuf;               // Object that we read from.
    StreamBuf* object_getting_from_my_buffer;   // Object reading our buffer.
  };

 protected:
  //---------------------------------------------------------------------------
  // Protected attributes:
  //

  // The devices whose constructor this StreamBuf was passed to.
  InputDevice* m_idevice;
  OutputDevice* m_odevice;

  // Count of number of devices.
  int m_device_counter;

 protected:
  //---------------------------------------------------------------------------
  // Private Destructor
  //

  // Should only be called by release()
  ~StreamBuf() { Dout(dc::io, "~StreamBuf() [" << (void*)this << ']'); }

 public:
  //---------------------------------------------------------------------------
  // Which InputDevice/OutputDevice object(s) is/are pointing to me?

  void set_input_device(InputDevice* device);
  void set_output_device(OutputDevice* device);

  // When both (or the only) associated devices call this function,
  // then we delete ourselfs.
  bool release(FileDescriptor const* device);

 protected:
  //---------------------------------------------------------------------------
  // Manipulators and accessors that are called from InputBuffer/OutputBuffer.

  // Returns the number of bytes that can be read directly from memory
  // from position igptr(). Do not return 0 unless the buffer is empty.
  size_t force_next_contiguous_number_of_bytes()
  {
    size_t contiguous_size = ishowmanyc();
    if (!contiguous_size && iunderflow() != EOF)
    {
      contiguous_size = ishowmanyc();
#ifdef CWDEBUG
      if (!contiguous_size)
        DoutFatal(dc::core, "StreamBuf needs fixing");
#endif
    }
    return contiguous_size;
  }

  // Returns the number of bytes that can be written directly into memory
  // at position pptr() at this moment.
  size_t available_contiguous_number_of_bytes() const { return epptr() - pptr(); }

  // Same as above, but doesn't return 0 unless out of memory or buffer full.
  size_t force_available_contiguous_number_of_bytes()
  {
    size_t contiguous_size = epptr() - pptr();
    if (contiguous_size == 0 && overflow(0) != EOF)     // Write a dummy byte '\0'
    {
      pbump(-1);                                        // Erase dummy byte
      contiguous_size = epptr() - pptr();
    }
    return contiguous_size;
  }

  // Call this when the buffer should be reduced in size.
  void reduce_buffer();

  // Should be called to make sure that the buffer also decreases.
  inline void reduce_buffer_if_empty();

  // Called to speed up a read of `n' number of characters.
  std::streamsize xsgetn(char* s, std::streamsize n) override { return input_streambuf->ixsgetn(s, n); }

  // Called to speed up a write of `n' number of characters.
  std::streamsize xsputn(char const* s, std::streamsize n) override;
};

//
// Interface classes
//

// Reading from a device:

class Dev2Buf : public StreamBuf
{
 public:
  using StreamBuf::StreamBuf;

  // Writing by the device:
  size_t dev2buf_contiguous() const                             // Return the number of bytes that can be written directly
      { return available_contiguous_number_of_bytes(); }        //  into memory at position dev2buf_ptr() at this moment.
  size_t dev2buf_contiguous_forced()                            // Same as above, but doesn't return 0 unless
      { return force_available_contiguous_number_of_bytes(); }  //  out of memory or buffer full.
  char* dev2buf_ptr() const { return pptr(); }                  // Get pointer to put area.
  void dev2buf_bump(int n) { pbump(n); }                        // Bump pointer `n' bytes.

  // Administration:
  void reduce_buf_if_empty() { reduce_buffer_if_empty(); }      // Should be called to make sure that the buffer also decreases.
};

// Writing to a device:

class Buf2Dev : public StreamBuf
{
 public:
  using StreamBuf::StreamBuf;

  // Reading by the device:
  size_t buf2dev_contiguous()                                   // Returns the number of bytes that can be read directly
      { return next_contiguous_number_of_bytes(); }             // from memory from position buf2dev_ptr().
  size_t buf2dev_contiguous_forced()                            // Returns the number of bytes that can be read directly
      { return force_next_contiguous_number_of_bytes(); }       // from memory from position buf2dev_ptr().
                                                                // Does not return 0 unless the buffer is empty.
  char* buf2dev_ptr() const { return igptr(); }                 // Get pointer to get area.
  void buf2dev_bump(int n) { igbump(n); }                       // Bump pointer `n' bytes.

  // Called when `async_flush' or `close' is called etc.
  // Classes derived from `StreamBuf' should override this function
  // so that it doesn't return until the buffer is emptied.
  int sync() override;
  // Alternatively, this can be called, i.e. for non-streams, whenever anything was
  // written to the buffer to make sure that it is written out.
  void flush();
};

// Linking two devices together:

class LinkBuffer : public Dev2Buf
{
 public:
  LinkBuffer(InputDevice* input_device, OutputDevice* output_device,
      size_t minimum_blocksize, size_t buffer_full_watermark, size_t max_alloc) :
    Dev2Buf(minimum_blocksize, buffer_full_watermark, max_alloc)
    { set_input_device(input_device); set_output_device(output_device); }

  //-----------------------------------------------------------
  // DUPLICATE METHODS OF Buf2Dev (maybe only be called by the BRT).
  size_t buf2dev_contiguous() { return next_contiguous_number_of_bytes(); }
  size_t buf2dev_contiguous_forced() { return force_next_contiguous_number_of_bytes(); }
  char* buf2dev_ptr() const { return igptr(); }
  void buf2dev_bump(int n) { igbump(n); }
  void flush();
  //-----------------------------------------------------------

  // Because this class has the same interface as Buf2Dev, it is safe to provide these casting operators:
  operator Buf2Dev&() { return *static_cast<Buf2Dev*>(static_cast<StreamBuf*>(this)); }
  operator Buf2Dev const&() const { return *static_cast<Buf2Dev const*>(static_cast<StreamBuf const*>(this)); }

  // Also allow converting a pointer.
  Buf2Dev* as_Buf2Dev() { return static_cast<Buf2Dev*>(static_cast<StreamBuf*>(this)); }
  Buf2Dev const* as_Buf2Dev() const { return static_cast<Buf2Dev const*>(static_cast<StreamBuf const*>(this)); }
};

// Program reading from a device:

class InputBuffer : public Dev2Buf
{
 public:
  InputBuffer(InputDevice* input_device, size_t minimum_blocksize, size_t buffer_full_watermark, size_t max_alloc) :
    Dev2Buf(minimum_blocksize, buffer_full_watermark, max_alloc) { set_input_device(input_device); }

  // Stuff below reads from the input buffer and therefore should be BRT.

  // Raw binary access (instead of using istream):
  char* raw_gptr() const { return igptr(); }                      // Get pointer to get area.
  void raw_gbump(int n) { igbump(n); }                            // Bump pointer `n' bytes.
  size_t raw_sgetn(char* s, size_t n) { return ixsgetn(s, n); }   // Read `n' bytes and copy them to `s'.

  // Administration:
  void raw_reduce_buffer_if_empty() { brt_reduce_buffer_if_empty(); }// Should be called to make sure that the buffer also decreases.
};

// Program writing to a device:

class OutputBuffer : public Buf2Dev
{
 public:
  OutputBuffer(OutputDevice* output_device, size_t minimum_blocksize, size_t buffer_full_watermark, size_t max_alloc) :
    Buf2Dev(minimum_blocksize, buffer_full_watermark, max_alloc) { set_output_device(output_device); }

  // Stuff below writes to the output buffer and therefore should be BWT.

  // Raw binary access (instead of using ostream):
  char* raw_pptr() const { return pptr(); }                     // Get pointer to put area.
  void raw_pbump(int n) { pbump(n); }                           // Bump pointer `n' bytes.
  size_t raw_sputn(char const* s, size_t n) { return xsputn(s, n); }    // Copy `n' bytes from `s' to the buffer.
};

// Initialize the input buffer pointer.
inline void StreamBuf::set_input_buffer(StreamBuf* b)
{
  input_streambuf = b;
  char* start = b->put_area_block_node->block_start();
  setg(start, start, start);
}

// Returns true if a string with length `len' is contiguous
// in the current get area of the output buffer.
// Called by the kernel.
// Read thread.
inline bool StreamBuf::is_contiguous(size_t len) const
{
#ifdef DEBUGDBSTREAMBUF
  if (igptr() < get_area_block_node->block_start() || igptr() > get_area_block_node->block_start() + get_area_block_node->get_size())
    DoutFatal( dc::core, "Ack! getpointer out of sync with get_area_block_node !" );
#endif
  return (igptr() + len <= get_area_block_node->block_start() + get_area_block_node->get_size());
}

inline void StreamBuf::reduce_buffer_if_empty()
{
  if (buffer_empty())
    reduce_buffer();
}

} // namespace evio

#ifdef CWDEBUG
inline std::ostream& operator<<(std::ostream& os, evio::MsgBlock const& msg_block)
{
  os.write(msg_block.get_start(), msg_block.get_size()); return os;
}

inline std::ostream& operator<<(std::ostream& os, evio::StreamBuf const& db)
{
  db.printOn(os);
  return os;
}
#endif
