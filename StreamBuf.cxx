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

// Define this (and DEBUG) to get an ENORMOUS ammount of debug output,
#undef DEBUGDBSTREAMBUF

#include "sys.h"
#include "debug.h"
#include "StreamBuf.h"
#ifdef CWDEBUG
#include "libcwd/buf2str.h"
#else
#undef DEBUGDBSTREAMBUF
#endif
#include <cstdlib>

using namespace std;
using namespace libcwd;

#if defined(CWDEBUG) && !defined(DOXYGEN)
NAMESPACE_DEBUG_CHANNELS_START
channel_ct io("IO");
NAMESPACE_DEBUG_CHANNELS_END
#endif

namespace evio {

#ifdef CWDEBUG
void StreamBuf::printOn(ostream& os) const
{
  os << "----------------------------------------------------------------------" << endl;
  os << "max_alloc = " << get_max_alloc() << "; buffer_full_watermark = " << max_used_size;
  os << "; current_number_of_blocks = " << output_buffer.size() << endl;
  os << "Block nodes: " << endl;
  unsigned int block_count = 0;
  size_t total_size = 0;
  os << "Start\t\tSize\n";
  for (MemoryBlocksBuffer::const_iterator i(output_buffer.begin()); i != output_buffer.end(); ++i)
  {
    MemoryBlock const* block(*i);
    os << (void*)block->block_start() << '\t' << block->get_size() << endl;
    total_size += block->get_size();
    ++block_count;
  }
  if (block_count != output_buffer.size())
    DoutFatal(dc::core, "Counted inconsistent number of blocks!");
  os << "Total size: " << total_size << endl;
  if (total_size != output_buffer.get_total_block_size())
    DoutFatal(dc::core, "Inconsistent total allocated size!");
  os << "get_area_block_node = " << (void*)get_area_block_node;
  os << "; put_area_block_node = " << (void*)put_area_block_node << endl;
  void* volatile ptr = (void*)gptr();
  os << "get area: " << (void*)ieback() << " - " << (void*)igptr() << "(" << igptr() - ieback() << ")" << " - " << (void*)iegptr() << "(" << iegptr() - ieback() << ")";
#if CWDEBUG_ALLOC
  os << "\t[ " << find_alloc(ieback())->start() << " (" << find_alloc(ieback())->size() << ") ]";
#endif
  os << endl;
  os << "put area: " << (void*)pbase() << " - " << (void*)pptr() << "(" << pptr() - pbase() << ")" << " - " << (void*)epptr() << "(" << epptr() - pbase() << ")";
#if CWDEBUG_ALLOC
  os << "\t[ " << find_alloc(pbase())->start() << " (" << find_alloc(pbase())->size() << ") ]";
#endif
  os << endl;
#if CWDEBUG_ALLOC
  if ((char*)find_alloc(ieback())->start() + sizeof(MemoryBlock) != ieback())
    DoutFatal(dc::core, "get area points to non-allocated block !");
  if (igptr() != ieback() && (char*)find_alloc(igptr() - 1)->start() + sizeof(MemoryBlock) != ieback())
    DoutFatal(dc::core, "get area get pointer points outside allocated block !");
  if (iegptr() != ieback() && (char*)find_alloc(iegptr() - 1)->start() + sizeof(MemoryBlock) != ieback())
    DoutFatal(dc::core, "end of get area points outside allocated block !");
  if ((char*)find_alloc(pbase())->start() + sizeof(MemoryBlock) != pbase())
    DoutFatal(dc::core, "put area points to non-allocated block !");
  if (pptr() != pbase() && (char*)find_alloc(pptr() - 1)->start() + sizeof(MemoryBlock) != pbase())
    DoutFatal(dc::core, "put area put pointer points outside allocated block !");
  if (epptr() != pbase() && (char*)find_alloc(epptr() - 1)->start() + sizeof(MemoryBlock) != pbase())
    DoutFatal(dc::core, "end of put area points outside allocated block !");
#endif
  os << "Total string length: " << total_size - (igptr() - ieback()) - (epptr() - pptr()) << endl;
  for (MemoryBlocksBuffer::const_iterator i(output_buffer.begin()); i != output_buffer.end(); ++i)
  {
    MemoryBlock const* block2(*i);
    os << "[" << (void*)block2 << "] ";
    if (block2 == get_area_block_node && block2 == put_area_block_node)
      os << "\"" << buf2str(igptr(), pptr() - igptr()) << "\"" << endl;     // Print from igptr() to pptr().
    else if (block2 == get_area_block_node)
      os << "\"" << buf2str(igptr(), block2->get_size() - (igptr() - ieback())) << endl;      // Print from igptr() to the end of the buffer.
    else if (block2 == put_area_block_node)
      os << buf2str(block2->block_start(), pptr() - pbase()) << "\"" << endl;   // Print from start of buffer to pptr().
    else
      os << buf2str(block2->block_start(), block2->get_size()) << endl;         // Print the whole buffer.
  }
  if (ieback() != get_area_block_node->block_start() ||
      pbase() != put_area_block_node->block_start() ||
      epptr() != pbase() + put_area_block_node->get_size() ||
      (get_area_block_node == put_area_block_node && iegptr() > pptr()) ||
      iegptr() > ieback() + get_area_block_node->get_size() ||
      igptr() < ieback() || igptr() > iegptr() ||
      pptr() < pbase() || pptr() > epptr())
    DoutFatal(dc::core, "Pointers inconsistent");
  os << "----------------------------------------------------------------------" << endl;
}
#endif

StreamBuf::int_type StreamBuf::overflow(int_type c)
{
#ifdef DEBUGDBSTREAMBUF
  cerr << "overflow(" << (char)c << "):" << endl;
  printOn(cerr);
#endif
  if (c == static_cast<int_type>(EOF))
    return 0;
  if (!output_buffer.push_back(new_block_size()))
    return static_cast<int_type>(EOF);
  put_area_block_node = output_buffer.back();
  setp(put_area_block_node->block_start(), put_area_block_node->block_start() + put_area_block_node->get_size());
  *pptr() = c;
  pbump(1);
#ifdef DEBUGDBSTREAMBUF
  printOn(cerr);
#endif
  return 0;
}

int StreamBuf::iunderflow(void)
{
#ifdef DEBUGDBSTREAMBUF
  cerr << "iunderflow(void):" << endl;
  printOn(cerr);
#endif
  if (get_area_block_node == put_area_block_node)
  {
    if (igptr() == pptr())
    {
      // The buffer is empty
      reduce_buffer();
#ifdef DEBUGDBSTREAMBUF
      cerr << "Returning EOF" << endl;
      printOn(cerr);
#endif
      return EOF;
    }
    isetg(ieback(), igptr(), pptr());
  }
  else
  {
    register char* start = get_area_block_node->block_start();
    if (igptr() == start + get_area_block_node->get_size())
    {
      output_buffer.pop_front();
      get_area_block_node = output_buffer.front();
      start = get_area_block_node->block_start();
      if (get_area_block_node == put_area_block_node)
      {
	if (pptr() == start)
	{
	  setp(pbase(), epptr());		// Buffer empty, set pointers
	  isetg(start, start, start);		// at beginning of single block
#ifdef DEBUGDBSTREAMBUF
	  cerr << "Returning EOF" << endl;
	  printOn(cerr);
#endif
	  return EOF;
	}
	isetg(start, start, pptr());
      }
      else
	isetg(start, start, start + get_area_block_node->get_size());
    }
    else
      isetg(ieback(), igptr(), start + get_area_block_node->get_size());
  }
#ifdef DEBUGDBSTREAMBUF
  printOn(cerr);
#endif
  return 0;
}

StreamBuf::int_type StreamBuf::ipbackfail(int_type c)
{
#ifdef DEBUGDBSTREAMBUF
  cerr << "ipbackfail(" << c << ")" << endl;
  printOn(cerr);
#endif
  if (c == static_cast<int_type>(EOF))
  {
#ifdef DEBUGDBSTREAMBUF
    cerr << "Returning 0" << endl;
    printOn(cerr);
#endif
    return 0;
  }
  if (igptr() > get_area_block_node->block_start())
  {
    igbump(-1);
    *igptr() = c;
#ifdef DEBUGDBSTREAMBUF
    printOn(cerr);
#endif
    return 0;
  }
  if (!output_buffer.push_front(new_block_size()))
  {
#ifdef DEBUGDBSTREAMBUF
    cerr << "Out of memory, returning EOF" << endl;
    printOn(cerr);
#endif
    return static_cast<int_type>(EOF);
  }
  get_area_block_node = output_buffer.front();
  register char* start = get_area_block_node->block_start();
  isetg(start, start + get_area_block_node->get_size() - 1, start + get_area_block_node->get_size());
  *igptr() = c;
#ifdef DEBUGDBSTREAMBUF
  printOn(cerr);
#endif
  return 0;
}

std::streamsize StreamBuf::ishowmanyc(void)
{
  if (get_area_block_node == put_area_block_node)
    isetg(ieback(), igptr(), pptr());
  else if (iegptr() < ieback() + get_area_block_node->get_size())
    isetg(ieback(), igptr(), ieback() + get_area_block_node->get_size());
  return iegptr() - igptr();
}

streamsize StreamBuf::ixsgetn(char* s, streamsize n)
{
#ifdef DEBUGDBSTREAMBUF
  cerr << "StreamBuf::ixsgetn(s, " << n << ")" << endl;
  printOn(cerr);
#endif

  if (get_area_block_node == put_area_block_node)
  {
    register char* _igptr = igptr();
    register char* _pptr = pptr();
    register streamsize len = _pptr - _igptr;
    if (n <= len)
    {
      memcpy(s, _igptr, n);
      isetg(ieback(), _igptr + n, _pptr);
#ifdef DEBUGDBSTREAMBUF
      printOn(cerr);
      cerr << "Returning " << n << endl;
#endif
      return n;
    }
    memcpy(s, _igptr, len);
    isetg(pbase(), pbase(), pbase());	// Buffer empty, set pointers to start of single block
    setp(pbase(), epptr());		//
#ifdef DEBUGDBSTREAMBUF
    printOn(cerr);
    cerr << "Returning " << len << endl;
#endif
    return len;
  }
  register streamsize len = ieback() + get_area_block_node->get_size() - igptr();
  if (n <= len)
  {
    memcpy(s, igptr(), n);
    isetg(ieback(), igptr() + n, ieback() + get_area_block_node->get_size());
#ifdef DEBUGDBSTREAMBUF
    printOn(cerr);
    cerr << "Returning " << n << endl;
#endif
    return n;
  }
  memcpy(s, igptr(), len);
  n -= len;
  s += len;
  output_buffer.pop_front();
  get_area_block_node = output_buffer.front();
  while (get_area_block_node != put_area_block_node)
  {
    if ((size_t)n <= get_area_block_node->get_size())
    {
      register char* start = get_area_block_node->block_start();
      memcpy(s, start, n);
      isetg(start, start + n, start + get_area_block_node->get_size());
#ifdef DEBUGDBSTREAMBUF
      printOn(cerr);
      cerr << "Returning " << len + n << endl;
#endif
      return len + n;
    }
    register size_t block_size = get_area_block_node->get_size();
    memcpy(s, get_area_block_node->block_start(), block_size);
    len += block_size;
    n -= block_size;
    s += block_size;
    output_buffer.pop_front();
    get_area_block_node = output_buffer.front();
  }
  register streamsize left = pptr() - pbase();
  if (n <= left)
  {
    memcpy(s, pbase(), n);
    isetg(pbase(), pbase() + n, pptr());
#ifdef DEBUGDBSTREAMBUF
    printOn(cerr);
    cerr << "Returning " << len + n << endl;
#endif
    return len + n;
  }
  memcpy(s, pbase(), left);
  isetg(pbase(), pbase(), pbase());	// Buffer empty, set pointers to start of single block.
  pbump(-left);				//
#ifdef DEBUGDBSTREAMBUF
  printOn(cerr);
  cerr << "Returning " << len + left << endl;
#endif
  return len + left;
}

streamsize StreamBuf::xsputn(char const* s, streamsize n)
{
#ifdef DEBUGDBSTREAMBUF
  cerr << "StreamBuf::xsputn(" << buf2str(s, n) << ", " << n << ")" << endl;
  printOn(cerr);
#endif
  register char const* sp = s;
  register streamsize m = n;
  register streamsize left = epptr() - pptr();
  if (m <= left)
  {
    memcpy(pptr(), sp, m);
    pbump(m);
  }
  else
  {
    memcpy(pptr(), sp, left);
    sp += left;
    m -= left;
    register size_t block_size = new_block_size();
    if (!output_buffer.push_back(block_size))
    {
#ifdef DEBUGDBSTREAMBUF
      cerr << "Buffer full, returning " << left << endl;
      printOn(cerr);
#endif
      pbump(left);
      return left;
    }
    put_area_block_node = output_buffer.back();
    while ((size_t)m > block_size)
    {
      memcpy(put_area_block_node->block_start(), sp, block_size);
      sp += block_size;
      m -= block_size;
      if (!output_buffer.push_back(new_block_size()))
      {
#ifdef DEBUGDBSTREAMBUF
	cerr << "Buffer full, returning" << (s - sp) << endl;
	printOn(cerr);
#endif
	pbump(block_size);
	return s - sp;
      }
      put_area_block_node = output_buffer.back();
      block_size = put_area_block_node->get_size();
    }
    memcpy(put_area_block_node->block_start(), sp, m);
    setp(put_area_block_node->block_start(), put_area_block_node->block_start() + block_size);
    pbump(m);
  }
#ifdef DEBUGDBSTREAMBUF
  cerr << "Returning " << n << endl;
  printOn(cerr);
#endif
  return n;
}

StreamBuf::StreamBuf(size_t minimum_blocksize, size_t max_alloc, size_t buffer_full_watermark) :
    max_used_size(buffer_full_watermark), output_buffer(max_alloc), idevice(NULL), odevice(NULL), device_counter(0)
{
  Dout(dc::io, "this = " << (void*)this << "; StreamBuf(" << minimum_blocksize << ", " << buffer_full_watermark << ", " << max_alloc << ')');
#ifdef CWDEBUG
  if (minimum_blocksize < 64)
    Dout(dc::warning, "StreamBuf with a minimum_blocksize smaller then 64 !");
  if (((minimum_blocksize - 1) & minimum_blocksize) != 0)
    DoutFatal(dc::core, "Please use a minimum_blocksize that is a power of 2 for StreamBuf");
#endif
  log2_min_buf_size = 6; // log(64)/log(2)
  while (minimum_blocksize > 64)
  {
    log2_min_buf_size++;
    minimum_blocksize = minimum_blocksize >> 1;
  }
  output_buffer.push_front((1 << log2_min_buf_size) - malloc_overhead_c - sizeof(MemoryBlock));
  get_area_block_node = put_area_block_node = output_buffer.front();
  input_dbstreambuf = this;
  register char* start = get_area_block_node->block_start();
  setp(start, start + put_area_block_node->get_size());
  isetg(start, start, start);
}

size_t StreamBuf::new_block_size(void) const
{
  register size_t nl = used_size();
  register size_t l2 = get_log2_min_buf_size();
  register long l = (nl < 2048 ? nl : 2048) + malloc_overhead_c - 1;

  if (l >= 2047)
    nl = (((nl - 1) >> 11) + 1) << 11;
  else
    for (nl = 1 << l2, l = l >> l2; l > 0; nl = nl << 1)
      l = l >> 1;
  return nl - malloc_overhead_c - sizeof(MemoryBlock);
}

void StreamBuf::reduce_buffer(void)
{
  size_t new_block_size = minimum_block_size();
  if (get_area_block_node->used() == 1)		// Only used by buffer
  {
    // Reuse the same block (slightly faster then allocating a new block)
    if (get_area_block_node->get_size() > new_block_size)
      output_buffer.reduce_total_block_size(get_area_block_node->reduce_block(new_block_size));
  }
  else
  {
    // Release the current block
    output_buffer.pop_front();
    // Allocate a new block
    output_buffer.push_back(new_block_size);
    get_area_block_node = put_area_block_node = output_buffer.back();	// There is only a single block
  }
  char* start = get_area_block_node->block_start();
  isetg(start, start, start);
  setp(start, start + new_block_size);		// note: get_area_block_node == put_area_block_node (the buffer is empty)
}

int StreamBuf::sync(void)
{
  //FIXME return ((odevice && odevice->sync(this)) || (idevice && idevice->sync(NULL)));
  return 0;
}

void StreamBuf::idevice_del(void)
{
  DoutFatal(dc::core, "When do we get here?");
  //FIXME idevice->del();
}

void StreamBuf::odevice_del(void)
{
  DoutFatal(dc::core, "When do we get here?");
  //FIXME odevice->del();
}

bool StreamBuf::release(IOBase* device)
{
#ifdef CWDEBUG
  if (device_counter == 0)
  {
    DoutFatal(dc::core,
	"\n\tCalling `StreamBuf::release' while `device_counter' equals 0."
	"\n\tAlways allocate a `StreamBuf' with `new' and pass it" <<
	"\n\tto either a `dbbuf_fd_dtct<INPUT>' or `dbbuf_fd_dtct<OUTPUT>'," <<
	"\n\tor to both by passing it to iodbbuf_fd_dtct<INPUT, OUTPUT>." <<
	"\n\t(Where INPUT must be an `InputDevice' and OUTPUT must be an `OutputDevice').");
  }
#endif
  if (--device_counter == 0)
  {
    delete this;
    return true;
  }
  else
  {
    // Resetting the devices is necessary because of `sync'.
    //FIXME uncomment once InputDevice/OutputDevice are declared again.
//    if (device == idevice)
//      idevice = NULL;
//    else if (device == static_cast<IOBase*>(odevice))
//      odevice = NULL;

    Dout(dc::malloc, "this = " << (void*)this << "; Calling StreamBuf::release " <<
	device_counter << " device left (" << idevice << ", " << odevice << ')');

    return false;
  }
}

} // namespace evio
