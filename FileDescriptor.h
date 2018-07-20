// evio -- Event Driven I/O support.
//
//! @file
//! @brief Declaration of namespace evio; class IOBase, InputDevice, OutputDevice, no_input_ct and no_output_ct.
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

#include "evio.h"
#include "StreamBuf.h"
#include "utils/AIRefCount.h"

class EventLoopThread;

namespace evio {

class no_input_ct;	// Classes used for dummy linkage to an input/output device.
class no_output_ct;

class input_link_ct;	// Base classes for use with objects that read
class output_link_ct;	// from output buffers, or write to input buffers
                        // of other objects.

class InputDevice;	// Base classes for general linkage to an input/output device.
class OutputDevice;

class read_input_ct;	// Base classes with a default read(2), write(2)
class write_output_ct;  // implementation.

class istream_ct;	// Same as InputDevice with istream interface.
class ostream_ct;	// Same as OutputDevice with ostream interface.

class read_istream_ct;	// Same as read_input_ct with istream interface.
class write_ostream_ct; // Same as write_output_ct with ostream interface.

/******************************************************************************

                                 OVERVIEW

Introduction
------------

The classes `InputDevice' and `OutputDevice' define some default input/output
characteristics, but do not define methods related to decoding or buffering.

The other input/output classes above override one or more of the virtual
functions of `InputDevice' and/or `OutputDevice'.  The following virtual
functions are not overridden by any of the default classes in this file:
`can_be_removed' and `fd_done'.  The first determines whether the object
must be removed while the latter is called when the object is actual being
removed.

From any of these functions you can call del() to remove the whole object
as usual (fire-and-forget).  It doesn't `delete' the object immedeately
but just marks it for removal (see `can_be_removed').

virtual functions of InputDevice
--------------------------------

  virtual void read_from_fd(int fd);
    // Data is available for reading from fd.
    //
    // This method should call `stop_input_device' when no more reading
    // is needed or wanted (for instance, when the buffer is too full).
    // It should call `reduce_buffer_if_empty' to make sure that the
    // buffer reduces size.
    // Access to the buffer should be implemented by means of calling
    // methods of Dev2Buf.
    //
    // This method is overridden by no_input_ct.

  virtual void read_returned_zero();
    // read(2) returned the value 0.
    // Interpretation depends on what kind of fd it is; for example, when
    // fd is a file it means EOF, when fd is a socket it means that the
    // the connection was closed.
    //
    // The default calls `del()'.

  virtual void read_error(int err)
    // The fatal error err occurred; we stopped reading the fd.
    // The default behaviour is to del() this object.

  virtual void data_received(char const* new_data, size_t rlen);
    // New data was read from the fd.
    // The default behavior is to do nothing.
    //
    // This method is overridden by read_input_ct.

virtual functions of OutputDevice
---------------------------------

  virtual void write_to_fd(int fd);
    // Data can be written from the buffer to the fd.
    //
    // This method should call `stop_output_device' when no more writting
    // is currently possible or needed (for instance, when the buffer is
    // empty).
    // Access to the buffer should be implemented by means of calling
    // methods of `streambuf'.
    //
    // This method is overridden by no_output_ct.

  virtual void write_error(int err);
    // write(2) returned a (fatal) error. Take action according to `err'.

virtual functions of read_input_ct
----------------------------------

  void data_received(char const* new_data, size_t rlen) override;
    // Overrides InputDevice::data_received. Calls the two virtual
    // functions below.

  virtual size_t end_of_msg_finder(char const* new_data, size_t rlen) const = 0;
    // Called by the default read_input_ct::data_received.
    //
    // This method should be implemented by a user class and return a value
    // larger than zero, the length of the next message, when a complete message
    // is available. Zero otherwise.

  virtual void decode(MsgBlock msg) = 0;
    // Called by the default read_input_ct::data_received when end_of_msg_finder
    // found a new message. Msg is the new, contiguous, message.
    //
    // This method should be implemented by a user class.

******************************************************************************/

// Set filedescriptor fd to non-blocking.
void set_nonblocking(int fd);

//=============================================================================
//
// class IOBase
//
// Virtual base class for IO Devices.
// This class takes care of the life-time of an Input-, Output- or IO-Device.
//

class IOBase : public AIRefCount
{
  using flags_t = uint32_t;
 protected:
  static flags_t constexpr FDS_RW        = 0x60000000;
  static flags_t constexpr FDS_W         = 0x40000000;
  static flags_t constexpr FDS_R         = 0x20000000;
  static flags_t constexpr FDS_CHK_EMPTY = 0x10000000;
  static flags_t constexpr FDS_ALIVE     = 0x70000000;
  static flags_t constexpr FDS_REMOVE    = 0x08000000;
  static flags_t constexpr FDS_DEAD      = 0x04000000;
  static flags_t constexpr INTERNAL_FDS_DONT_CLOSE = 0x02000000;
  static flags_t constexpr FDS_DONT_CLOSE_ON_DEL   = 0x01000000;
  static flags_t constexpr FDS_LINKED    = 0x00800000;
  static flags_t constexpr FDS_DISABLED  = 0x00400000;
  static flags_t constexpr FDS_BLOCKING  = 0x00200000;
#ifdef CWDEBUG
  static flags_t constexpr FDS_DEBUG     = 0x00100000;
#endif

  flags_t m_flags;

 private:
  virtual void init_input_device(int) { }
  virtual void init_output_device(int) { }

 protected:
  virtual void start_input_device() { }
  virtual void start_output_device() { }
  virtual void stop_input_device() { }
  virtual void stop_output_device() { }
  virtual void disable_input_device() { }
  virtual void disable_output_device() { }
  virtual void enable_input_device() { }
  virtual void enable_output_device() { }

 protected:
  IOBase() : m_flags(0) { }
#ifdef CWDEBUG
  ~IOBase() { Dout(dc::notice, "Destructing IOBase [" << (void*)this << "]"); }
#endif

  //---------------------------------------------------------------------------
  // Accessors for m_flags; not really _needed_ public, but here they are.
  //

  // Return true if this object is a base class of OutputDevice.
  bool writable_type(void) const { return m_flags & FDS_W; }

  // Return true if this object is a base class of InputDevice.
  bool readable_type(void) const { return m_flags & FDS_R; }

  // Returns true if this object is a writable device.
  bool is_writable(void) const { return (m_flags & (FDS_W|FDS_DISABLED|FDS_DEAD)) == FDS_W; }

  // Returns true if this object is a readable device.
  // Note: Objects that should be removed must not be read.
  bool is_readable(void) const { return (m_flags & (FDS_R|FDS_DISABLED|FDS_REMOVE|FDS_DEAD)) == FDS_R; }

  // Returns true if this object is not associated with a working fd.
  // Note: Isn't this always the same as !is_open() ?
  bool is_dead(void) const { return m_flags & FDS_DEAD; }

  // Returns true if this object is disabled at this moment.
  bool is_disabled(void) const { return m_flags & FDS_DISABLED; }

  // Returns true if the underlaying file descriptor wasn't set to non-blocking yet.
  bool is_blocking(void) const { return m_flags & FDS_BLOCKING; }

  // Returns true if this object is scheduled for removal.
  bool must_be_removed(void) const { return m_flags & FDS_REMOVE; }

  // Returns true if this object/node is linked into libev.
  bool is_linked(void) const { return m_flags & FDS_LINKED; }

  // Accessor that returns true if the write buffer is possibly empty.
  // We assume that the buffer is possibly empty when the last call
  // to select(2) we didn't monitor this object for writability.
  bool writebuf_is_maybe_empty(void) const { return m_flags & FDS_CHK_EMPTY; }

  // Return true if this object is marked that it should not close its fd.
  bool dont_close(void) { return m_flags & INTERNAL_FDS_DONT_CLOSE; }

  // Return true if this object is marked that it should not close
  // its fd when del() is called.
  bool dont_close_on_del(void) { return m_flags & FDS_DONT_CLOSE_ON_DEL; }

#ifdef CWDEBUG
  // Returns true if this object is used for debug output.
  // If it is, then no new debug output will be produced by the kernel while handling it.
  bool is_debug_channel(void) const { return m_flags & FDS_DEBUG; }
#endif

 public:
  // (Re)Initialize the FileDescriptor.
  void init(int fd)
  {
    init_input_device(fd);
    init_output_device(fd);
    // Make file descriptor non-blocking by default.
    set_nonblocking(fd);
    // Set FDS_REMOVE so that either start_input_device() or start_output_device() will increment the ref count.
    m_flags |= FDS_REMOVE;
  }

  void start()
  {
    start_input_device();
    start_output_device();
  }

  void stop()
  {
    stop_input_device();
    stop_output_device();
  }

  void disable(void)
  {
    disable_input_device();
    disable_output_device();
  }

  void enable(void)
  {
    enable_input_device();
    enable_output_device();
  }

  void del()
  {
    if (!must_be_removed())     // Has not already been marked for removal?
    {
      m_flags |= FDS_REMOVE;
      stop_input_device();
      intrusive_ptr_release(this);
    }
  }
};


//=============================================================================
//
// class InputDevice
//
// Base class for classes that define Input characteristics.
//

class InputDevice : public virtual IOBase
{
 public:
  // The default blocksize for your `dbstreambuf_ct' input buffers, used
  // when you don't pass that size to the constructors.
  static size_t constexpr default_blocksize_c = 512;

 protected:
  //---------------------------------------------------------------------------
  // The input buffer
  //

  InputBuffer* m_ibuffer;       // A pointer to the input buffer.

 private:
  //---------------------------------------------------------------------------
  // Inferface with libev.
  //

  friend EventLoopThread;       // Needs access to m_input_watcher.
  ev_io m_input_watcher;        // The watcher.

  // Override base class member functions.
  void init_input_device(int fd) override;
 protected:
  void start_input_device() override;
  void stop_input_device() override;

 protected:
  //---------------------------------------------------------------------------
  // Constructor:
  //
  // Protected: May only be constructed by dbbuf_fd_dtct.
  //
  InputDevice(Dev2Buf* ibuf) : m_ibuffer(static_cast<InputBuffer*>(ibuf))
  {
    // Mark that InputDevice is a derived class.
    m_flags |= FDS_R;
    // Give m_input_watcher known values; cause is_active() to return false.
    ev_io_init(&m_input_watcher, InputDevice::s_evio_cb, -1, EV_UNDEF);
    // Tell the input buffer that we are the linked input device.
    m_ibuffer->set_input_device(this);
  }

  // Destructor.
  ~InputDevice()
  {
    // Delete the input buffer if it is no longer needed.
    m_ibuffer->release(this);
  }

  // Disallow copy constructing.
  InputDevice(InputDevice const&) = delete;

 private:
  // The call back used by libev.
  static void s_evio_cb(EV_P_ ev_io* w, int) { static_cast<InputDevice*>(w->data)->read_from_fd(w->fd); }

 public:
  //---------------------------------------------------------------------------
  // Public accessors:
  //

  // Supposed to be used for passing it to other device constructors.
  Dev2Buf* rddbbuf(void) const { return m_ibuffer; }

  // Returns true if our watcher is linked in with libev.
  bool is_active() const { return ev_is_active(&m_input_watcher); }

 public:
  //---------------------------------------------------------------------------
  // Public manipulators:
  //

  void disable_input_device() override
  {
    m_flags |= FDS_DISABLED;
    stop_input_device();
  }

  void enable_input_device() override
  {
    m_flags &= ~FDS_DISABLED;
    if (is_readable())
      start_input_device();
  }

 protected:
  // Event: 'fd' is readable.
  //
  // This default implementation reads data from the fd into the buffer until
  // 1) read(2) reads less than the available buffer space, or
  // 2) read(2) returns 0.
  // 3) The buffer is full and max_alloc was reached.
  // When the buffer is full or when read(2) returns 0, stop_input_device is called.
  // When read(2) returns 0 then (after calling stop_input_device) the virtual function
  // read_returned_zero is called.
  // When read(2) returns an error other then EINTR (or when EINTR was caused by SIGPIPE),
  // EAGAIN or EWOULDBLOCK it calls the virtual function read_error, see below.
  virtual void read_from_fd(int fd);

  // The default behaviour is to del() the object.
  virtual void read_returned_zero(void) { del(); }

  // The default behaviour is to del() this object.
  virtual void read_error(int UNUSED_ARG(err)) { del(); }

  // The default behavior is to do nothing.
  virtual void data_received(char const* new_data, size_t rlen);
};


//=============================================================================
//
// class OutputDevice
//
// Base class for classes that define Output characteristics.
//

class OutputDevice : public virtual IOBase
{
 public:
  // The default blocksize for your `dbstreambuf_ct' output buffers, used
  // when you don't pass that size to the constructors.
  static size_t constexpr default_blocksize_c = 2048;

 protected:
  //---------------------------------------------------------------------------
  // The output buffer
  //

  OutputBuffer* m_obuffer;      // A pointer to the output buffer.

 private:
  //---------------------------------------------------------------------------
  // Inferface with libev.
  //

  friend EventLoopThread;       // Needs access to m_output_watcher.
  ev_io m_output_watcher;       // The watcher.

  // Override base class member functions.
  void init_output_device(int fd) override;
 protected:
  void start_output_device() override;
  void stop_output_device() override;

 protected:
  //---------------------------------------------------------------------------
  // Constructor:
  //
  // Protected: May only be constructed by dbbuf_fd_dtct.
  //
  OutputDevice(Buf2Dev* obuf) : m_obuffer(static_cast<OutputBuffer*>(obuf))
  {
    // Mark that OutputDevice is a derived class.
    m_flags |= FDS_W;
    // Give m_output_watcher known values; cause is_active() to return false.
    ev_io_init(&m_output_watcher, OutputDevice::s_evio_cb, -1, EV_UNDEF);
    // Tell the input buffer that we are the linked input device.
    m_obuffer->set_output_device(this);
  }

  // Destructor.
  ~OutputDevice()
  {
    // Delete the output buffer if it is no longer needed.
    m_obuffer->release(this);
  }

  // Disallow copy constructing.
  OutputDevice(OutputDevice const&) = delete;

 protected:
  // Event: fd is writable.
  //
  // This default implementation writes data from the buffer to the fd until
  // 1) the buffer is empty, or
  // 2) write(2) wrote less than the number of bytes passed to it, or
  // 3) write(2) returned an error other than EAGAIN or EINTR, or
  // 4) EAGAIN != EWOULDBLOCK and EAGAIN happens twice in a row, or
  // 5) write(2) returned EINTR caused by SIGPIPE.
  // When write(2) returns an error other then EINTR (or when EINTR was caused by SIGPIPE),
  // EAGAIN or EWOULDBLOCK it calls the virtual function write_error, see below.
  virtual void write_to_fd(int fd);

  // This default implementation `close's the object (which removes it).
  virtual void write_error(int UNUSED_ARG(err)) { close(); }

  // Returns true if the output buffer is empty.
  virtual bool writebuf_is_really_empty(void) const = 0;

 private:
  // The call back used by libev.
  static void s_evio_cb(EV_P_ ev_io* w, int) { static_cast<OutputDevice*>(w->data)->write_to_fd(w->fd); }

 public:
  //---------------------------------------------------------------------------
  // Public accessors:
  //

  // Supposed to be used for passing it to other device constructors.
  Buf2Dev* rddbbuf(void) const { return m_obuffer; }

  // Returns true if our watcher is linked in with libev.
  bool is_active() const { return ev_is_active(&m_output_watcher); }

 public:
  //---------------------------------------------------------------------------
  // Public manipulators:
  //

  void disable_output_device() override
  {
    m_flags |= FDS_DISABLED;
    stop_output_device();
  }

  void enable_output_device() override
  {
    m_flags &= ~FDS_DISABLED;
    if (is_writable())
      start_output_device();
  }

  void close()
  {
    DoutFatal(dc::core, "FIXME");
  }
};

//=============================================================================
//
// class no_input_ct
//

class no_input_ct : public InputDevice
{
 protected:
  no_input_ct(InputBuffer* ibuf) : InputDevice(ibuf) { }
  void read_from_fd(int) override { stop_input_device(); }
};


//=============================================================================
//
// class istream_ct
//

class istream_ct : public InputDevice, public std::istream
{
  using iostreamT = std::istream;
 protected:
  istream_ct(InputBuffer* ibuf) : InputDevice(ibuf), std::istream(ibuf) { }
};


//=============================================================================
//
// class no_output_ct
//

class no_output_ct : public OutputDevice
{
 protected:
  no_output_ct(OutputBuffer* obuf) : OutputDevice(obuf) { }
  void write_to_fd(int) override
  {
    DoutFatal(dc::core, "Don't write data to \"no_output_ct\"");
  }

  // We never have anything to write.
  bool writebuf_is_really_empty() const override { return true; }
};


//=============================================================================
//
// class ostream_ct
//

class ostream_ct : public OutputDevice, public std::ostream
{
  using iostreamT = std::ostream;
 protected:
  ostream_ct(OutputBuffer* obuf) :OutputDevice(obuf), std::ostream(obuf) { }
};


//=============================================================================
//
// class read_input_ct
//
// Base class for reading from a device, using a general read(2) implementation.
//

class read_input_ct : public InputDevice
{
 protected:
  // The pure virtual function end_of_msg_finder(char const*, size_t) const
  // is called when new data is received.
  //
  // When end_of_msg_finder returns a value > 0, then the pure virtual
  // function decode is called.
  void data_received(char const* new_data, size_t rlen) override;

  // Returns the size of the first message, or 0 if there is no complete message.
  virtual size_t end_of_msg_finder(char const*, size_t) const = 0;

  // Called by the default data_received (see above).
  // Msg is a contiguous message.
  virtual void decode(MsgBlock msg) = 0;

 protected:
  //---------------------------------------------------------------------------
  // Constructor:
  //

  read_input_ct(InputBuffer* ibuf) : InputDevice(ibuf) { }
};

//=============================================================================
//
// class read_istream_ct
//

class read_istream_ct : public read_input_ct, public std::istream
{
  using iostreamT = std::istream;
 protected:
  read_istream_ct(InputBuffer* ibuf) : read_input_ct(ibuf), std::istream(ibuf) { }
};

//=============================================================================
// class link_ct
//
// The common part of input_link_ct and output_link_ct
//

class link_ct
{
 public:
  using buffer_ct = LinkBuffer;     // The type of the "link buffer".

 public:
  // The default blocksize for your `dbstreambuf_ct' link buffers, used
  // when you don't pass that size to the constructors.
  static size_t constexpr default_blocksize_c = 2048;

 protected:
  //---------------------------------------------------------------------------
  // Constructor:
  //

  link_ct(void) { }

  // Disallow copy constructing.
  link_ct(link_ct const&) = delete;
};


//=============================================================================
//
// class input_link_ct
//
// Base class which only reads data from its fd and writes it into the buffer.
//

class input_link_ct : public InputDevice, public link_ct
{
 public:
  using buflinkT = output_link_ct;

 public:
  // Used default posix mode for opening files, when you don't pass it to
  // the constructor.
  static int constexpr mode = std::ios_base::in;

 public:
  //---------------------------------------------------------------------------
  // Public accessor:
  //

  // Supposed to be used for passing it to other device constructors.
  Dev2Buf* rddbbuf(void) const { return m_ibuffer; }

 protected:
  //---------------------------------------------------------------------------
  // Constructor:
  //
  // Protected: May only be constructed by dbbuf_fd_dtct
  //

  input_link_ct(LinkBuffer* lbuf) : InputDevice(lbuf) { }
};


//=============================================================================
//
// class write_output_ct
//
// Base class to write to a device, using a default write(2) implementation.
//

class write_output_ct : public OutputDevice
{
 public:
  //---------------------------------------------------------------------------
  // Accessors
  //

  // Returns true if the output buffer is empty.
  bool writebuf_is_really_empty(void) const override;

 protected:
  //---------------------------------------------------------------------------
  // Constructor:
  //

  write_output_ct(OutputBuffer* obuf) : OutputDevice(obuf) { }
};


//=============================================================================
//
// class write_ostream_ct
//

class write_ostream_ct : public write_output_ct, public std::ostream
{
  using iostreamT = std::ostream;
 protected:
  write_ostream_ct(OutputBuffer* obuf) : write_output_ct(obuf), std::ostream(obuf) { }
};


//=============================================================================
//
// class output_link_ct
//
// Base class which only reads data from its buffer and writes it to the fd.
//

class output_link_ct : public OutputDevice, public link_ct
{
 public:
  using buflinkT = input_link_ct;

  // Used default posix mode for opening files, when you don't pass it to the constructor.
  static int constexpr mode = std::ios_base::out;

 protected:
  //---------------------------------------------------------------------------
  // Constructor:
  //
  // Protected: May only be constructed by dbbuf_fd_dtct
  //

  output_link_ct(LinkBuffer* lbuf) : OutputDevice(lbuf->as_Buf2Dev()) { }

 public:
  //---------------------------------------------------------------------------
  // Accessors
  //

  // Returns true if the output buffer is empty.
  bool writebuf_is_really_empty(void) const override;
};

} // namespace evio

#if defined(CWDEBUG) && !defined(DOXYGEN)
NAMESPACE_DEBUG_CHANNELS_START
extern channel_ct evio;
NAMESPACE_DEBUG_CHANNELS_END
#endif
