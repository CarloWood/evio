// evio -- Event Driven I/O support.
//
//! @file
//! @brief Declaration of namespace evio; class MemoryBlocksBuffer, MsgBlock, StreamBuf, InputBuffer, OutputBuffer and LinkBuffer.
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

#pragma once

#include "sys.h"
#include <deque>
#include <cstdlib>              // Needed for malloc(2) etc.
#include <streambuf>
#include <new>
#include <iostream>
#include <unistd.h>             // Needed for read(2) and write(2)
#include "debug.h"

#if defined(CWDEBUG) && !defined(DOXYGEN)
NAMESPACE_DEBUG_CHANNELS_START
extern channel_ct io;           // IO specific debug output.
NAMESPACE_DEBUG_CHANNELS_END
#endif

namespace evio {

//!
// @brief The memory overhead of a call to malloc() in bytes.
//
// Determined during configuration. When N bytes are allocated
// with malloc(N) then it reality N + malloc_overhead_c bytes
// are used.
static int constexpr malloc_overhead_c = CW_MALLOC_OVERHEAD;

// Forward declarations.
class IOBase;
class InputDevice;
class OutputDevice;
class MsgBlock;
class StreamBuf;

//=============================================================================
//
// struct MemoryBlock
//
// Dynamically allocated memory block
//

//
// This object uses a somewhat dirty programming trick.
// This object is put at the beginning of a large memory block that is
// allocated with malloc.
//

struct MemoryBlock
{
  friend class MsgBlock;        // Needs access to used_cnt;
 private:
  //---------------------------------------------------------------------------
  // Attributes
  //

  size_t block_size;            // Size of allocated block in bytes
  unsigned int used_cnt;        // Reference counter

 public:
  //---------------------------------------------------------------------------
  // Constructors/destructor/assigment
  //

  static MemoryBlock* create(size_t size)
  {
    MemoryBlock* memory_block = (MemoryBlock*)malloc(sizeof(MemoryBlock) + size);
    AllocTag((char*)memory_block, "MemoryBlock (" << sizeof(MemoryBlock) << " bytes) + buffer allocation");
    memory_block->block_size = size;
    memory_block->used_cnt = 1;
    return memory_block;
  }

  void release()
  {
    if (--used_cnt == 0)
      free(this);
  }

 private: // Don't use any of default stuff!
  MemoryBlock() = delete;
  MemoryBlock(MemoryBlock const&) = delete;
  ~MemoryBlock() = delete;
  MemoryBlock& operator=(MemoryBlock const&) = delete;

 public:
  //---------------------------------------------------------------------------
  // Public accessors
  //

  // Returns the start of the allocated memory block.
  char* block_start() const { return const_cast<char*>(reinterpret_cast<char const*>(this) + sizeof(MemoryBlock)); }

  // Returns the current size of the allocated memory block.
  size_t get_size() const { return block_size; }

  size_t used() const { return used_cnt; }

 public:
  //---------------------------------------------------------------------------
  // Manipulator
  //

  // Set memory block to the new block size.  Returns the reduced size in bytes.
  // `new_block_size' must be equal or smaller then the current block size.
  size_t reduce_block(size_t new_block_size)
  {
#ifdef DEBUGDBSTREAMBUF
    ASSERT(block_size >= new_block_size);           // realloc should not relocate memory block
#endif
    size_t amount = block_size - new_block_size;
    block_size = new_block_size;
    void* unused __attribute__((unused)) = realloc(this, sizeof(MemoryBlock) + block_size);
    return amount;
  }
};

//=============================================================================
//
// class MemoryBlocksBuffer
//
class MemoryBlocksBuffer
{
  typedef std::deque<MemoryBlock*> container_type;
 private:
  container_type memory_block_list;                     // List with dynamically allocated blocks
  size_t total_block_size;                              // Total amount of currently allocated memory.
  size_t max_alloc;                                     // Maximum allowed number of allocated bytes.

 public:
  typedef container_type::iterator iterator;
  typedef container_type::const_iterator const_iterator;
  typedef container_type::reference reference;
  typedef container_type::const_reference const_reference;
  typedef container_type::size_type size_type;
  typedef container_type::difference_type difference_type;
  typedef container_type::value_type value_type;
  typedef container_type::reverse_iterator reverse_iterator;
  typedef container_type::const_reverse_iterator const_reverse_iterator;

 public:
  iterator begin() { return memory_block_list.begin(); }
  const_iterator begin() const { return memory_block_list.begin(); }
  iterator end() { return memory_block_list.end(); }
  const_iterator end() const { return memory_block_list.end(); }
  reverse_iterator rbegin() { return memory_block_list.rbegin(); }
  const_reverse_iterator rbegin() const { return memory_block_list.rbegin(); }
  reverse_iterator rend() { return memory_block_list.rend(); }
  const_reverse_iterator rend() const { return memory_block_list.rend(); }
  reference front() { return memory_block_list.front(); }
  const_reference front() const { return memory_block_list.front(); }
  reference back() { return memory_block_list.back(); }
  const_reference back() const { return memory_block_list.back(); }

 public:
  //---------------------------------------------------------------------------
  // Constructors
  // Use default copy constructor
  // Use default destructor

  // Constructor, sets a maximum buffer size.
  MemoryBlocksBuffer(size_t max_alloc_) : total_block_size(0), max_alloc(max_alloc_) { }

  ~MemoryBlocksBuffer()
  {
    for (iterator i(begin()); i != end(); ++i)
      (*i)->release();
  }

  //---------------------------------------------------------------------------
  // Assignment operator:
  // Use default assignment operator.

  //---------------------------------------------------------------------------
  // Public accessors:
  //

  // Accessor returning the current number of allocated blocks.
  size_type size() const { return memory_block_list.size(); }

  // size() of the largest possible container.
  size_type max_size() const { return memory_block_list.max_size(); }

  // Returns `true' if the container is empty.
  bool empty() const { return memory_block_list.empty(); }

  // Accessor that returns the total number of allocated bytes.
  size_t get_total_block_size() const { return total_block_size; }

  // Accessor for `max_alloc'.
  size_t get_max_alloc() const { return max_alloc; }

  //---------------------------------------------------------------------------
  // Manipulator methods of `MemoryBlocksBuffer'
  //

  bool push_front(size_t size)
  {
    if ((total_block_size += size) <= max_alloc)
    {
      memory_block_list.push_front(MemoryBlock::create(size));
      return true;
    }
    total_block_size -= size;
    return false;
  }

  bool push_back(size_t size)
  {
    if ((total_block_size += size) <= max_alloc)
    {
      memory_block_list.push_back(MemoryBlock::create(size));
      return true;
    }
    total_block_size -= size;
    return false;
  }

  // Erase the first element.
  void pop_front()
  {
    MemoryBlock* memory_block = memory_block_list.front();
    total_block_size -= memory_block->get_size();
    memory_block_list.pop_front();
    memory_block->release();
  }

  // Erase the last element.
  void pop_back()
  {
    MemoryBlock* memory_block = memory_block_list.back();
    total_block_size -= memory_block->get_size();
    memory_block_list.pop_back();
    memory_block->release();
  }

 public:// FIXME make private and use friend later
  void reduce_total_block_size(size_t amount) { total_block_size -= amount; }

 private:
  // Don't use copy constructor
  MemoryBlocksBuffer(MemoryBlocksBuffer const&) = delete;
};

//=============================================================================
//
// class MsgBlock
//
class MsgBlock
{
 private:
  char const* start;
  size_t size;
  MemoryBlock* memory_block;

 public:
  MsgBlock(char const* start_, size_t size_, MemoryBlock* memory_block_) : start(start_), size(size_), memory_block(memory_block_)
  {
    ASSERT(start >= memory_block->block_start() && start + size <= memory_block->block_start() + memory_block->get_size());
    memory_block->used_cnt++;
  }

  ~MsgBlock() { memory_block->release(); }

  MsgBlock(MsgBlock const& msg_block) : start(msg_block.start), size(msg_block.size), memory_block(msg_block.memory_block)
  {
    memory_block->used_cnt++;
  }

  MsgBlock& operator=(MsgBlock const& msg_block)
  {
    if (this == &msg_block)
      return *this;
    memory_block->release();
    start = msg_block.start;
    size = msg_block.size;
    memory_block = msg_block.memory_block;
    ASSERT(start >= memory_block->block_start() && start + size <= memory_block->block_start() + memory_block->get_size());
    memory_block->used_cnt++;
    return *this;
  }

  char const* get_start() const { return start; }
  size_t get_size() const { return size; }
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
  // together is `max_alloc'. When this value is reached, `overflow' will
  // return EOF.
  // The method `buffer_full' returns true when the number of buffered
  // bytes in the output buffer exceed `buffer_full_watermark'.
  // After using this constructor, the input buffer is the same as the
  // output buffer. Use `set_input_buffer' to change this.
  StreamBuf(size_t minimum_blocksize,
            size_t max_alloc = std::numeric_limits<size_t>::max(),              // The default causes push_back and push_front to only fail when we actually run out of memory.
            size_t buffer_full_watermark = std::numeric_limits<size_t>::max()); // The default causes buffer_full() to never return true.

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
  bool buffer_full() const { return (used_size() >= max_used_size); }

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
  int_type overflow(int_type c = EOF) override;

  // Called when a block is empty.
  int_type underflow() override { return input_streambuf->iunderflow(); }

  // Called when a putback failed.
  int_type pbackfail(int_type c) override { return input_streambuf->ipbackfail(c); }

  // Though ANSI C++, not implemented in libg++-2.7.1. Used by libcw.
  // This should return the number of contiguous characters at the
  // beginning of the get area.
  // Note: libcw demands that this function does not return '0' unless
  // the buffer is empty (this is not explicitly demanded by ANSI).
  std::streamsize showmanyc() override { return input_streambuf->ishowmanyc(); }

 protected:
  //---------------------------------------------------------------------------
  // Protected manipulators that work on the get area or on the put area of the
  // input buffer. All these functions start with an 'i'.
  //

  // Advance get pointer of input buffer `n' positions.
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

#if 0 //def NEED_STREAMBUF_CONST_BUGFIX
 protected:
  //---------------------------------------------------------------------------
  // If `eback', `gptr', `egptr' etc. do not have the `const' type qualifier,
  // give it them here:
  //

  class access_streambuf : public std::streambuf {
  public:
    typedef char* (std::streambuf::*cast_const)() const;
    friend class StreamBuf;
  };

  char* eback() const { return ((this->*((access_streambuf::cast_const)std::streambuf::eback))()); }
  char* gptr()  const { return ((this->*((access_streambuf::cast_const)std::streambuf::gptr))()); }
  char* egptr() const { return ((this->*((access_streambuf::cast_const)std::streambuf::egptr))()); }
  char* pbase() const { return ((this->*((access_streambuf::cast_const)std::streambuf::pbase))()); }
  char* pptr()  const { return ((this->*((access_streambuf::cast_const)std::streambuf::pptr))()); }
  char* epptr() const { return ((this->*((access_streambuf::cast_const)std::streambuf::epptr))()); }
#endif // NEED_STREAMBUF_CONST_BUGFIX

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
  bool release(IOBase* device);

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
};

// Linking two devices together:

class LinkBuffer : public Dev2Buf
{
 public:
  using Dev2Buf::Dev2Buf;

  //-----------------------------------------------------------
  // DUPLICATE METHODS OF Buf2Dev.
  size_t buf2dev_contiguous() { return next_contiguous_number_of_bytes(); }
  size_t buf2dev_contiguous_forced() { return force_next_contiguous_number_of_bytes(); }
  char* buf2dev_ptr() const { return igptr(); }
  void buf2dev_bump(int n) { igbump(n); }
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
  using Dev2Buf::Dev2Buf;

  // Raw binary access (instead of using istream):
  char* raw_gptr() const { return igptr(); }                    // Get pointer to get area.
  void raw_gbump(int n) { igbump(n); }                          // Bump pointer `n' bytes.
  size_t raw_sgetn(char* s, size_t n) { return ixsgetn(s, n); } // Read `n' bytes and copy them to `s'.
};

// Program writing to a device:

class OutputBuffer : public Buf2Dev
{
 public:
  using Buf2Dev::Buf2Dev;

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
inline bool StreamBuf::is_contiguous(size_t len) const
{
#ifdef DEBUGDBSTREAMBUF
  if (igptr() < get_area_block_node->block_start() || igptr() > get_area_block_node->block_start() + get_area_block_node->get_size())
    DoutFatal( dc::core, "Ack! getpointer out of sync with get_area_block_node !" );
#endif
  return (igptr() + len <= get_area_block_node->block_start() + get_area_block_node->get_size());
}

inline void StreamBuf::set_input_device(InputDevice* device)
{
  // Don't pass a StreamBuf to more than one device.
  // Also note set_input_device should only be called from the constructor of an InputDevice, don't call it directly.
  ASSERT(!m_idevice);
  ++m_device_counter;
  m_idevice = device;
}

inline void StreamBuf::set_output_device(OutputDevice* device)
{
  // Don't pass a StreamBuf to more than one device.
  // Also note set_output_device should only be called from the constructor of an OutputDevice, don't call it directly.
  ASSERT(!m_odevice);
  ++m_device_counter;
  m_odevice = device;
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
