// evio -- Event Driven I/O support.
//
//! @file
//! @brief Declaration of namespace evio; class memory_blocks_buffer_ct, msg_block_ct, dbstreambuf_ct, input_buffer_ct, output_buffer_ct and link_buffer_ct.
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
#include <cstdlib>		// Needed for malloc(2) etc.
#include <unistd.h>		// Needed for read(2) and write(2)
#include <streambuf>
#include <new>
#include <iostream>
#include "debug.h"

#if defined(CWDEBUG) && !defined(DOXYGEN)
NAMESPACE_DEBUG_CHANNELS_START
extern channel_ct io;		// IO specific debug output.
NAMESPACE_DEBUG_CHANNELS_END
#endif

namespace evio {

static int constexpr malloc_overhead_c = CW_MALLOC_OVERHEAD;

// Forward declarations.
class IOBase;
class InputDevice;
class OutputDevice;
class msg_block_ct;
class dbstreambuf_ct;

//=============================================================================
//
// struct memory_block_st
//
// Dynamically allocated memory block
//

//
// This object uses a somewhat dirty programming trick.
// This object is put at the beginning of a large memory block that is
// allocated with malloc.
//

struct memory_block_st
{
  friend class msg_block_ct;	// Needs access to used_cnt;
 private:
  //---------------------------------------------------------------------------
  // Attributes
  //

  size_t block_size;		// Size of allocated block in bytes
  unsigned int used_cnt;	// Reference counter

 public:
  //---------------------------------------------------------------------------
  // Constructors/destructor/assigment
  //

  static memory_block_st* create(size_t size)
      {
	memory_block_st* memory_block = (memory_block_st*)malloc(sizeof(memory_block_st) + size);
	AllocTag((char*)memory_block, "memory_block_st (" << sizeof(memory_block_st) << " bytes) + buffer allocation");
	memory_block->block_size = size;
	memory_block->used_cnt = 1;
	return memory_block;
      }

  void release(void)
      {
        if (--used_cnt == 0)
	  free(this);
      }

 private: // Don't use any of default stuff!
  memory_block_st(void) { }
  ~memory_block_st() { }
  memory_block_st(memory_block_st const&) { }
  memory_block_st& operator=(memory_block_st const&) { return *this; }

 public:
  //---------------------------------------------------------------------------
  // Public accessors
  //

  char* block_start(void) const { return const_cast<char*>(reinterpret_cast<char const*>(this) + sizeof(memory_block_st)); }
    // Returns the start of the allocated memory block.

  size_t get_size(void) const { return block_size; }
    // Returns the current size of the allocated memory block.

  size_t used(void) const { return used_cnt; }

 public:
  //---------------------------------------------------------------------------
  // Manipulator
  //

  size_t reduce_block(size_t new_block_size)
      {
#ifdef DEBUGDBSTREAMBUF
	ASSERT(block_size >= new_block_size);           // realloc should not relocate memory block
#endif
	size_t ammount = block_size - new_block_size;
	block_size = new_block_size;
	void* unused __attribute__((unused)) = realloc(this, sizeof(memory_block_st) + block_size);
	return ammount;
      }
    // Set memory block to the new block size.  Returns the reduced size in bytes.
    // `new_block_size' must be equal or smaller then the current block size.
};

#ifdef CWDEBUG
std::ostream& operator<<(std::ostream& os, msg_block_ct const& msg);
#endif

//=============================================================================
//
// class memory_blocks_buffer_ct
//
class memory_blocks_buffer_ct
{
  typedef std::deque<memory_block_st*> container_type;
 private:
  container_type memory_block_list;			// List with dynamically allocated blocks
  size_t total_block_size;				// Total ammount of currently allocated memory.
  size_t max_alloc;					// Maximum allowed number of allocated bytes.

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
  iterator begin(void) { return memory_block_list.begin(); }
  const_iterator begin(void) const { return memory_block_list.begin(); }
  iterator end(void) { return memory_block_list.end(); }
  const_iterator end(void) const { return memory_block_list.end(); }
  reverse_iterator rbegin(void) { return memory_block_list.rbegin(); }
  const_reverse_iterator rbegin(void) const { return memory_block_list.rbegin(); }
  reverse_iterator rend(void) { return memory_block_list.rend(); }
  const_reverse_iterator rend(void) const { return memory_block_list.rend(); }
  reference front(void) { return memory_block_list.front(); }
  const_reference front(void) const { return memory_block_list.front(); }
  reference back(void) { return memory_block_list.back(); }
  const_reference back(void) const { return memory_block_list.back(); }

 public:
  //---------------------------------------------------------------------------
  // Constructors
  // Use default copy constructor
  // Use default destructor

  memory_blocks_buffer_ct(size_t max_alloc_) : total_block_size(0), max_alloc(max_alloc_) { }
      // Constructor, sets a maximum buffer size.

  ~memory_blocks_buffer_ct()
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

  size_type size(void) const { return memory_block_list.size(); }
      // Accessor returning the current number of allocated blocks.

  size_type max_size(void) const { return memory_block_list.max_size(); }
      // size() of the largest possible container.

  bool empty(void) const { return memory_block_list.empty(); }
      // Returns `true' if the container is empty.

  size_t get_total_block_size(void) const { return total_block_size; }
      // Accessor that returns the total number of allocated bytes.

  size_t get_max_alloc(void) const { return max_alloc; }
    // Accessor for `max_alloc'

  //---------------------------------------------------------------------------
  // Manipulator methods of `memory_blocks_buffer_ct'
  //

  bool push_front(size_t size)
      {
	if ((total_block_size += size) <= max_alloc)
	{
	  memory_block_list.push_front(memory_block_st::create(size));
	  return true;
	}
	total_block_size -= size;
	return false;
      }

  bool push_back(size_t size)
      {
	if ((total_block_size += size) <= max_alloc)
	{
	  memory_block_list.push_back(memory_block_st::create(size));
          return true;
        }
	total_block_size -= size;
	return false;
      }

  void pop_front(void)
      {
        memory_block_st* memory_block = memory_block_list.front();
        total_block_size -= memory_block->get_size();
	memory_block_list.pop_front();
	memory_block->release();
      }
    // Erase the first element.

  void pop_back(void)
      {
        memory_block_st* memory_block = memory_block_list.back();
        total_block_size -= memory_block->get_size();
	memory_block_list.pop_back();
	memory_block->release();
      }
    // Erase the last element.

 public:// FIXME make private and use friend later
  void reduce_total_block_size(size_t ammount) { total_block_size -= ammount; }

 private:
  // Don't use copy constructor
  memory_blocks_buffer_ct(memory_blocks_buffer_ct const&) { }
};

//=============================================================================
//
// class msg_block_ct
//
class msg_block_ct
{
 private:
  char const* start;
  size_t size;
  memory_block_st* memory_block;
 public:
  msg_block_ct(char const* start_, size_t size_, memory_block_st* memory_block_) :
      start(start_), size(size_), memory_block(memory_block_)
      {
        ASSERT(start >= memory_block->block_start() && start + size <= memory_block->block_start() + memory_block->get_size());
	memory_block->used_cnt++;
      }
  ~msg_block_ct() { memory_block->release(); }
  msg_block_ct(msg_block_ct const& msg_block) :
      start(msg_block.start), size(msg_block.size), memory_block(msg_block.memory_block)
      {
	memory_block->used_cnt++;
      }
  msg_block_ct& operator=(msg_block_ct const& msg_block)
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
  char const* get_start(void) const { return start; }
  size_t get_size(void) const { return size; }
};

inline std::ostream& operator<<(std::ostream& os, msg_block_ct const& msg_block)
{
  os.write(msg_block.get_start(), msg_block.get_size()); return os;
}

//=============================================================================
//
// class dbstreambuf_ct
//
// Dynamic Blocks STREAM BUFfer
//
// SYNOPSIS
//
// List of allocated blocks for the streambufs put area.
// Therefore, this list is associated with output (ostream).
// The get area of the streambuf that this object is associated
// with will get from 'our input buffer' which is another `dbstreambuf_ct'
// object pointed to by attribute `input_dbstreambuf'.
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

class dbstreambuf_ct : public std::streambuf
{
 public:
  //---------------------------------------------------------------------------
  // Constructor
  //

  dbstreambuf_ct(size_t minimum_blocksize, size_t buffer_full_watermark, size_t max_alloc_);
    // Construct a `dbstreambuf_ct' object. The minimum number of allocated
    // bytes for one block of the output buffer is `minimum_blocksize'.
    // The maximum possible number of total allocated bytes of all blocks
    // together is `max_alloc_'. When this value is reached, `overflow' will
    // return EOF.
    // The method `buffer_full' returns true when the number of buffered
    // bytes in the output buffer exceed `buffer_full_watermark'.
    // After using this constructor, the input buffer is the same as the
    // output buffer. Use `set_input_buffer' to change this.

 public:
  //---------------------------------------------------------------------------
  // Public initializers
  //

  void set_input_buffer(dbstreambuf_ct* b);

 public:
  //---------------------------------------------------------------------------
  // Public accessors
  //

  unsigned short get_log2_min_buf_size(void) const { return log2_min_buf_size; }
    // Returns the logarithm base 2 of minimum block size.
    // *undocumented*

  size_t minimum_block_size(void) const { return (1 << log2_min_buf_size) - malloc_overhead_c - sizeof(memory_block_st); }
    // Returns the minimum block size in bytes.

  bool has_multiple_blocks(void) const { return get_area_block_node != put_area_block_node; }
    // Returns `true' when this buffer currently has more then one block
    // allocated. This can be used to speed up read/write access methods.

  size_t unused_in_first_block(void) const { return gptr() - eback(); }
    // Return the number of unused bytes in the get area of the input buffer
    // *undocumented*

  size_t unused_in_last_block(void) const { return epptr() - pptr(); }
    // Return the number of unused bytes in the put area of the output buffer.
    // *undocumented*

  size_t used_size(void) const
      {
        return output_buffer.get_total_block_size() -
            object_getting_from_my_buffer->unused_in_first_block() -
            unused_in_last_block();
      }
    // Return the current number of valid bytes in the output buffer.
    //
    // Note: This assumes that the get area is the first block and the
    // put area is the last block.  This might change when pubseek() is added.

  size_t get_max_alloc(void) const { return output_buffer.get_max_alloc(); }
    // Return the maximum allowed ammount of allocated bytes for this buffer.

  size_t next_contiguous_number_of_bytes(void) const { return (iegptr() - igptr()); }
    // The ammount of contiguous bytes that can be read directly from the get area.

  bool is_contiguous(size_t len) const;
    // Returns true if a string with length `len' is contiguous
    // in the current get area of the output buffer.

  size_t new_block_size(void) const;
    // Calculate the size of the new block as a function of the currently
    // amount of buffered data.  The new size is adjusted for gnu malloc,
    // which doesn't hurt when you use another malloc.
    // *undocumented*

  bool buffer_full() const { return (used_size() >= max_used_size); }
    // Returns true if the output buffer is full.

  bool buffer_empty() const { return igptr() == pptr(); }
    // Returns true if output buffer is empty.

#ifdef CWDEBUG
  void printOn(std::ostream& o) const;
    // Print debug information in stream `o'.
    // *undocumented*
#endif

  // Undocumented (use outside of libcw is depricated)
  memory_block_st* get_get_area_block_node(void) const { return get_area_block_node; }
  memory_block_st* get_put_area_block_node(void) const { return put_area_block_node; }

 protected:
  //---------------------------------------------------------------------------
  // Get and put area of the `other' buffer.

  char* ieback(void) const { return input_dbstreambuf->eback(); }
    // Start of input buffer

  char* igptr(void) const { return input_dbstreambuf->gptr(); }
    // Next character in input buffer

  char* iegptr(void) const { return input_dbstreambuf->egptr(); }
    // End of input buffer

  char* ipbase(void) const { return input_dbstreambuf->pbase(); }
    // Return start of put area of our input buffer (called by kernel)

  char* ipptr(void) const { return input_dbstreambuf->pptr(); }
    // Return next write position in put area of our input buffer
    // (called by kernel).

  char* iepptr(void) const { return input_dbstreambuf->epptr(); }
    // Return end of put area of our input buffer (called by kernel)

//=============================================================================

 protected:
  //---------------------------------------------------------------------------
  // `streambuf' interface (See ANSI C++ draft)
  //
#if (__GNUC__ < 2) || (__GNUC__ == 2 && __GNUC_MINOR__ < 97)
  typedef int int_type;
#endif

  virtual int_type overflow(int_type c = EOF);
    // Called when a block is full.

  virtual int_type underflow(void) { return input_dbstreambuf->iunderflow(); }
    // Called when a block is empty.

  virtual int_type pbackfail(int_type c) { return input_dbstreambuf->ipbackfail(c); }
    // Called when a putback failed.

  virtual std::streamsize showmanyc(void) { return input_dbstreambuf->ishowmanyc(); }
    // Though ANSI C++, not implemented in libg++-2.7.1. Used by libcw.
    // This should return the number of contiguous characters at the
    // beginning of the get area.
    // Note: libcw demands that this function does not return '0' unless
    // the buffer is empty (this is not explicitly demanded by ANSI).

  virtual int sync(void);
    // Called when `async_flush' or `close' is called etc.
    // Classes derived from `dbstreambuf' should override this function
    // so that it doesn't return until the buffer is emptied.

 protected:
  //---------------------------------------------------------------------------
  // Protected manipulators that work on the get area or on the put area of the
  // input buffer. All these functions start with an 'i'.
  //

  void igbump(int n) { input_dbstreambuf->gbump(n); }
    // Advance get pointer of input buffer `n' positions.

  void isetg(char* eb, char* g, char* eg) { input_dbstreambuf->setg(eb, g, eg); }
    // (Re-)initialize the get area of the input buffer.

  std::streamsize ixsgetn(char* s, std::streamsize n);
    // Called by the object reading from my output buffer, reads `n'
    // number of characters into `s'.

  std::streamsize ishowmanyc(void);
    // Called by the object reading from my output buffer,
    // This should return the number of contiguous characters at the
    // beginning of the get area of my output buffer.

  int_type ipbackfail(int_type c);
    // Called by the object reading from my output buffer when
    // a `putback' fails.

  int iunderflow(void);
    // Called by the object reading from my output buffer, when the
    // end of the get area is reached.

  int ioverflow(int c = EOF) { return input_dbstreambuf->overflow(c); }
    // Write one character `c' to my input_buffer, should only be called
    // when the put area of the input buffer is full.

  std::streamsize ixsputn(char const* s, std::streamsize n)
      { return input_dbstreambuf->xsputn(s, n); }
    // Write `n' bytes from `s' to my input buffer.

  void ipbump(int n) { input_dbstreambuf->pbump(n); }
    // Advance the put pointer of the input buffer `n' characters.

  void isetp(char* p, char* ep) { input_dbstreambuf->setp(p, ep); }
    // Set the start and end of the put area of my input buffer.

#ifdef NEED_STREAMBUF_CONST_BUGFIX
 protected:
  //---------------------------------------------------------------------------
  // If `eback', `gptr', `egptr' etc. do not have the `const' type qualifier,
  // give it them here:
  //

  class access_streambuf : public std::streambuf {
  public:
    typedef char* (std::streambuf::*cast_const)(void) const;
    friend class dbstreambuf_ct;
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

  unsigned short log2_min_buf_size;
    // 2 ^ log2_min_buf_size - malloc_overhead_c - sizeof(memory_block_st), is minimum block size

  size_t max_used_size;
    // 'buffer_full' returns true when this ammount is buffered.

  memory_block_st* get_area_block_node;
    // Pointer to the get area - block object.

  memory_block_st* put_area_block_node;
    // Pointer to the put area - block object.

  memory_blocks_buffer_ct output_buffer;
    // List of allocated blocks for the streambufs 'put area',
    // associating `output_buffer' with output (ostream).

  union {
    dbstreambuf_ct* input_dbstreambuf;		   // Object that we read from
    dbstreambuf_ct* object_getting_from_my_buffer; // Object reading our buffer
  };
    // Optional pointer to list of allocated blocks for the streambufs
    // 'get area', associating `input_dbstreambuf' with input (istream).
    // If only one buffer is used, this should point to `this'.
    // The union symbolizes that only two objects of type `dbstreambuf_ct'
    // can be linked together, if three or more are used these should
    // be different pointers.

  InputDevice* idevice;
  void idevice_del(void);
    // `InputDevice' object that uses this buffer for input.

  OutputDevice* odevice;
  void odevice_del(void);
    // `OutputDevice' object that uses this buffer for output.

  int device_counter;
    // Count of number of devices.

 protected:
  //---------------------------------------------------------------------------
  // Private Destructor
  //

  ~dbstreambuf_ct(void) { }
    // Should only be called by release()

 private:
  //===========================================================================
  // The following methods are called from input_ct and output_ct.

  //friend class output_ct;
  //friend class input_ct;

  //---------------------------------------------------------------------------
  // Which input_ct/output_ct object(s) is/are pointing to me?

 public:
  void set_input_device(InputDevice* device);
  void set_output_device(OutputDevice* device);

  bool release(IOBase* device);
    // When both (or the only) associated devices call this function,
    // then we delete ourselfs.

 protected:
  //---------------------------------------------------------------------------
  // Manipulators and accessors that are called from input_buffer_ct/output_buffer_ct.

  size_t force_next_contiguous_number_of_bytes(void)
      {
	size_t tmp = ishowmanyc();
	if (!tmp && iunderflow() != EOF)
	{
	  tmp = ishowmanyc();
#ifdef CWDEBUG
          if (!tmp)
	    DoutFatal( dc::core, "dbstreambuf_ct needs fixing" );
#endif
	}
	return tmp;
      }
    // Returns the number of bytes that can be read directly from memory
    // from position igptr(). Do not return 0 unless the buffer is empty.

  size_t available_contiguous_number_of_bytes(void) const { return epptr() - pptr(); }
    // Returns the number of bytes that can be written directly into memory
    // at position pptr() at this moment.

  size_t force_available_contiguous_number_of_bytes(void)
      {
        if (overflow(0) == static_cast<int_type>(EOF))		// Write a dummy byte '\0'
          return 0;
        pbump(-1);			// Erase dummy byte
        return available_contiguous_number_of_bytes();
      }
    // Same as above, but doesn't return 0 unless out of memory or buffer full.

  void reduce_buffer(void);
    // Call this when the buffer should be reduced in size.

  inline void reduce_buffer_if_empty(void);
    // Should be called to make sure that the buffer also decreases.

  virtual std::streamsize xsgetn(char* s, std::streamsize n) { return input_dbstreambuf->ixsgetn(s, n); }
    // Called to speed up a read of `n' number of characters.

  virtual std::streamsize xsputn(char const* s, std::streamsize n);
    // Called to speed up a write of `n' number of characters.

};

//
// Interface classes
//

// Program reading from a device:

class input_buffer_ct : public dbstreambuf_ct
{
 public:
  input_buffer_ct(size_t minimum_blocksize, size_t buffer_full_watermark = (size_t)-1, size_t max_alloc = (size_t)-1) :
      dbstreambuf_ct(minimum_blocksize, buffer_full_watermark, max_alloc) { }

  // Raw binary access (instead of using istream):
  char* raw_gptr(void) const { return igptr(); }		// Get pointer to get area.
  void raw_gbump(int n) { igbump(n); }				// Bump pointer `n' bytes.
  size_t raw_sgetn(char* s, size_t n) { return ixsgetn(s, n); }	// Read `n' bytes and copy them to `s'.

  // Writing by the device:
  size_t dev2buf_contiguous(void) const				// Return the number of bytes that can be written directly
      { return available_contiguous_number_of_bytes(); }	//  into memory at position dev2buf_ptr() at this moment.
  size_t dev2buf_contiguous_forced(void)			// Same as above, but doesn't return 0 unless
      { return force_available_contiguous_number_of_bytes(); }	//  out of memory or buffer full.
  char* dev2buf_ptr(void) const { return pptr(); }		// Get pointer to put area.
  void dev2buf_bump(int n) { pbump(n); }			// Bump pointer `n' bytes.

  // Administration:
  void reduce_buf_if_empty(void) { reduce_buffer_if_empty(); }
    // Should be called to make sure that the buffer also decreases.
};

// Program writing to a device:

class output_buffer_ct : public dbstreambuf_ct
{
 public:
  output_buffer_ct(size_t minimum_blocksize, size_t buffer_full_watermark = (size_t)-1, size_t max_alloc = (size_t)-1) :
      dbstreambuf_ct(minimum_blocksize, buffer_full_watermark, max_alloc) { }

  // Raw binary access (instead of using ostream):
  char* raw_pptr(void) const { return pptr(); }			// Get pointer to put area.
  void raw_pbump(int n) { pbump(n); }				// Bump pointer `n' bytes.
  size_t raw_sputn(char* s, size_t n) { return xsputn(s, n); }	// Copy `n' bytes from `s' to the buffer.

  // Reading by the device:
  size_t buf2dev_contiguous(void) const				// Returns the number of bytes that can be read directly
      { return next_contiguous_number_of_bytes(); }		// from memory from position buf2dev_ptr().
  size_t buf2dev_contiguous_forced(void)			// Returns the number of bytes that can be read directly
      { return force_next_contiguous_number_of_bytes(); }	// from memory from position buf2dev_ptr().
      								// Does not return 0 unless the buffer is empty.
  char* buf2dev_ptr(void) const { return igptr(); }		// Get pointer to get area.
  void buf2dev_bump(int n) { igbump(n); }			// Bump pointer `n' bytes.
};

// Linking two devices together:

class link_buffer_ct : public dbstreambuf_ct
{
 public:
  link_buffer_ct(size_t minimum_blocksize, size_t buffer_full_watermark = (size_t)-1, size_t max_alloc = (size_t)-1) :
      dbstreambuf_ct(minimum_blocksize, buffer_full_watermark, max_alloc) { }

  // Writing by the device:
  size_t dev2buf_contiguous(void) const				// Return the number of bytes that can be written directly
      { return available_contiguous_number_of_bytes(); }	//  into memory at position dev2buf_ptr() at this moment.
  size_t dev2buf_contiguous_forced(void)			// Same as above, but doesn't return 0 unless
      { return force_available_contiguous_number_of_bytes(); }	//  out of memory or buffer full.
  char* dev2buf_ptr(void) const { return pptr(); }		// Get pointer to put area.
  void dev2buf_bump(int n) { pbump(n); }			// Bump pointer `n' bytes.

  // Administration:
  void reduce_buf_if_empty(void) { reduce_buffer_if_empty(); }
    // Should be called to make sure that the buffer also decreases.
 
  // Reading by the device:
  size_t buf2dev_contiguous(void) const				// Returns the number of bytes that can be read directly
      { return next_contiguous_number_of_bytes(); }		// from memory from position buf2dev_ptr().
  size_t buf2dev_contiguous_forced(void)			// Returns the number of bytes that can be read directly
      { return force_next_contiguous_number_of_bytes(); }	// from memory from position buf2dev_ptr().
      								// Does not return 0 unless the buffer is empty.
  char* buf2dev_ptr(void) const { return igptr(); }		// Get pointer to get area.
  void buf2dev_bump(int n) { igbump(n); }			// Bump pointer `n' bytes.
};

// Initialize the input buffer pointer.
inline void dbstreambuf_ct::set_input_buffer(dbstreambuf_ct* b)
{
  input_dbstreambuf = b;
  char* start = b->put_area_block_node->block_start();
  setg(start, start, start);
}

// Returns true if a string with length `len' is contiguous
// in the current get area of the output buffer.
// Called by the kernel.
inline bool dbstreambuf_ct::is_contiguous(size_t len) const
{
#ifdef DEBUGDBSTREAMBUF
  if (igptr() < get_area_block_node->block_start() || igptr() > get_area_block_node->block_start() + get_area_block_node->get_size())
    DoutFatal( dc::core, "Ack! getpointer out of sync with get_area_block_node !" );
#endif
  return (igptr() + len <= get_area_block_node->block_start() + get_area_block_node->get_size());
}

#ifdef CWDEBUG
inline std::ostream& operator<<(std::ostream& os, dbstreambuf_ct const& db)
{
  db.printOn(os);
  return os;
}
#endif

inline void dbstreambuf_ct::set_input_device(InputDevice* device)
{
  device_counter++;
  if (idevice)
    idevice_del();
  idevice = device;
}

inline void dbstreambuf_ct::set_output_device(OutputDevice* device)
{
  device_counter++;
  if (odevice)
    odevice_del();
  odevice = device;
}

inline void dbstreambuf_ct::reduce_buffer_if_empty(void)
{
  if (buffer_empty())
    reduce_buffer();
}

} // namespace evio
