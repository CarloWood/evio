// evio -- Event Driven I/O support.
//
//! @file
//! @brief Declaration of namespace evio; class IOBase, InputDevice, OutputDevice, InputDeviceStream, OutputDeviceStream, ReadInputDevice, ReadInputDeviceStream, WriteOutputDevice, WriteOutputDeviceStream, LinkInputDevice and LinkOutputDevice.
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
#include "EventLoopThread.h"
#include "utils/AIRefCount.h"

namespace evio {

class LinkInputDevice;	// Base classes for use with objects that read
class LinkOutputDevice;	// from output buffers, or write to input buffers
                        // of other objects.

class InputDevice;	// Base classes for general linkage to an input/output device.
class OutputDevice;

class ReadInputDevice;	// Base classes with a default read(2), write(2)
class WriteOutputDevice;  // implementation.

class InputDeviceStream;	// Same as InputDevice with istream interface.
class OutputDeviceStream;	// Same as OutputDevice with ostream interface.

class ReadInputDeviceStream;	// Same as ReadInputDevice with istream interface.
class WriteOutputDeviceStream; // Same as WriteOutputDevice with ostream interface.

/******************************************************************************

                                 OVERVIEW

Introduction
------------

The classes `InputDevice' and `OutputDevice' define some default input/output
characteristics and provide the hooks with libev, but do not define methods
related to decoding or buffering.

The other input/output classes above override one or more of the virtual
functions of `InputDevice' and/or `OutputDevice'.

virtual functions of IOBase
---------------------------

  virtual void closed();
    // The file descriptor(s) of this device were closed.
    //
    // This method is called after the filedescriptors were
    // just closed and can be used for certain cleanup in
    // derived classes.
    //
    // The default does nothing.

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

  virtual void read_returned_zero();
    // read(2) returned the value 0.
    // Interpretation depends on what kind of fd it is; for example, when
    // fd is a file it means EOF, when fd is a socket it means that the
    // the connection was closed.
    //
    // The default calls `close()'.

  virtual void read_error(int err)
    // The fatal error err occurred; we stopped reading the fd.
    //
    // The default calls `close()'.

  virtual void data_received(char const* new_data, size_t rlen);
    // New data was read from the fd.
    // The default behavior is to do nothing.
    //
    // This method is overridden by ReadInputDevice.

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

  virtual void write_error(int err);
    // write(2) returned a (fatal) error. Take action according to `err'.

virtual functions of ReadInputDevice
----------------------------------

  void data_received(char const* new_data, size_t rlen) override;
    // Overrides InputDevice::data_received. Calls the two virtual
    // functions below.

  virtual size_t end_of_msg_finder(char const* new_data, size_t rlen) = 0;
    // Called by the default ReadInputDevice::data_received.
    //
    // This method should be implemented by a user class and return a value
    // larger than zero, the length of the next message, when a complete message
    // is available. Zero otherwise.

  virtual void decode(MsgBlock msg) = 0;
    // Called by the default ReadInputDevice::data_received when end_of_msg_finder
    // found a new message. Msg is the new, contiguous, message.
    //
    // This method should be implemented by a user class.

******************************************************************************/

// Set filedescriptor fd to non-blocking.
void set_nonblocking(int fd);
// Return true if fd is a valid open filedescriptor.
bool is_valid(int fd);

//=============================================================================
//
// class IOBase
//
// Virtual base class for IO Devices.
// This class takes care of the life-time of an Input-, Output- or IO-Device.
//

class IOBase : public AIRefCount
{
 protected:
  using flags_t = uint32_t;
  static int constexpr disabled_shft = 2;
  static int constexpr open_shft = 4;
  static flags_t constexpr FDS_W                   = 0x80000000;
  static flags_t constexpr FDS_R                   = 0x40000000;
  static flags_t constexpr FDS_RW                  = FDS_R | FDS_W;
  static flags_t constexpr FDS_W_DISABLED          = 0x20000000;        // Must be FDS_W >> disabled_shft.
  static flags_t constexpr FDS_R_DISABLED          = 0x10000000;        // Must be FDS_R >> disabled_shft.
  static flags_t constexpr FDS_W_OPEN              = 0x08000000;        // Must be FDS_W >> open_shft.
  static flags_t constexpr FDS_R_OPEN              = 0x04000000;        // Must be FDS_R >> open_shft.
  static flags_t constexpr FDS_SAME                = 0x02000000;
  static flags_t constexpr FDS_REMOVE              = 0x01000000;
  static flags_t constexpr FDS_DEAD                = 0x00800000;
  static flags_t constexpr INTERNAL_FDS_DONT_CLOSE = 0x00400000;
  static flags_t constexpr FDS_LINKED              = 0x00200000;
#ifdef CWDEBUG
  static flags_t constexpr FDS_DEBUG               = 0x00100000;
#endif

  flags_t m_flags;

 private:
  // At least one of these must be overridden to initialize the appropriate device(s).
  // Both are called by init().
  virtual void init_input_device(int) { }
  virtual void init_output_device(int) { }

 protected:
  struct RefCountReleaser
  {
   private:
    AIRefCount* m_ptr;

   public:
    void execute()
    {
      if (m_ptr)
      {
        Dout(dc::io, "Decrementing ref count of device " << (void*)m_ptr << " to " << (m_ptr->ref_count() - 1));
        intrusive_ptr_release(m_ptr);
      }
      m_ptr = nullptr;
    }
    RefCountReleaser() : m_ptr(nullptr) { }
    ~RefCountReleaser() { execute(); }
    RefCountReleaser(RefCountReleaser&& releaser) { ASSERT(!m_ptr); m_ptr = releaser.m_ptr; releaser.m_ptr = nullptr; }
    RefCountReleaser& operator=(RefCountReleaser&& releaser) { ASSERT(!m_ptr); m_ptr = releaser.m_ptr; releaser.m_ptr = nullptr; return *this; }
    RefCountReleaser& operator+=(RefCountReleaser&& releaser)
    {
      if (m_ptr && releaser.m_ptr) { ASSERT(m_ptr == releaser.m_ptr); execute(); }
      m_ptr = releaser.m_ptr;
      releaser.m_ptr = nullptr;
      return *this;
    }
    void operator=(AIRefCount* ptr) { ASSERT(!m_ptr); m_ptr = ptr; }
    void reset() { m_ptr = nullptr; }
    operator bool() const { return m_ptr; }
  };

  // Requests.
  // Call these from derived classes to start watching, stop watching, temporarily disable and enable the device.
  virtual void start_input_device() { }
  virtual void start_output_device() { }
  virtual RefCountReleaser stop_input_device() { return RefCountReleaser(); }
  virtual RefCountReleaser stop_output_device() { return RefCountReleaser(); }
  virtual void disable_input_device() { }
  virtual void disable_output_device() { }
  virtual void enable_input_device() { }
  virtual void enable_output_device() { }
  virtual RefCountReleaser close_input_device() { return RefCountReleaser(); }
  virtual RefCountReleaser close_output_device() { return RefCountReleaser(); }

  // Queries.
  // Called to obtain the fd that init_input_device() was called with if that actually did initialize an input device; otherwise -1 is returned.
  virtual int get_input_fd() const { return -1; }
  // Called to obtain the fd that init_output_device() was called with if that actually did initialize an output device; otherwise -1 is returned.
  virtual int get_output_fd() const { return -1; }

  // Events.
  // The filedescriptor(s) of this device were just closed (close_fds() was called).
  // If INTERNAL_FDS_DONT_CLOSE is set than the fd(s) weren't really closed, but this method is still called.
  // When we get here the object is also marked as FDS_DEAD.
  virtual RefCountReleaser closed() { return RefCountReleaser(); }

 protected:
  IOBase() : m_flags(0) { }
  ~IOBase() { DoutEntering(dc::evio, "~IOBase() [" << (void*)this << "]"); }

  //---------------------------------------------------------------------------
  // Accessors for m_flags; not really _needed_ public, but here they are.
  //

  // Return true if this object is a base class of OutputDevice.
  bool writable_type() const { return m_flags & FDS_W; }

  // Return true if this object is a base class of InputDevice.
  bool readable_type() const { return m_flags & FDS_R; }

  // Returns true if this object is a writable device.
  bool is_writable() const { return (m_flags & (FDS_W|FDS_W_DISABLED|FDS_DEAD)) == FDS_W; }

  // Returns true if this object is a readable device.
  // Note: Objects that should be removed must not be read.
  bool is_readable() const { return (m_flags & (FDS_R|FDS_R_DISABLED|FDS_REMOVE|FDS_DEAD)) == FDS_R; }

  // Returns true if this object is not associated with a working fd.
  bool is_dead() const { return m_flags & FDS_DEAD; }

  // Returns true if this object is disabled at this moment.
  bool is_disabled() const { return m_flags & ((m_flags & FDS_RW) >> 8); }

  // Returns true if this object is write disabled at this moment (aka, is a writable device and writing is disabled).
  bool is_write_disabled() const { return m_flags & ((m_flags & FDS_W) >> 8); }

  // Returns true if this object is read disabled at this moment (aka, is a readable device and reading is disabled).
  bool is_read_disabled() const { return m_flags & ((m_flags & FDS_R) >> 8); }

  // Returns true if this object is scheduled for removal.
  bool must_be_removed() const { return m_flags & FDS_REMOVE; }

  // Returns true if this object/node is linked into libev.
  bool is_linked() const { return m_flags & FDS_LINKED; }

  // Return true if this object is marked that it should not close its fd.
  bool dont_close() const { return m_flags & INTERNAL_FDS_DONT_CLOSE; }

  // Return true if this object has at least one open filedescriptor.
  bool is_open() const { return m_flags & (m_flags & FDS_RW) >> open_shft; }

  // Return true if this object is marked as having an open fd for writing.
  bool is_open_w() const { return m_flags & FDS_W_OPEN; }

  // Return true if this object is marked as having an open fd for reading.
  bool is_open_r() const { return m_flags & FDS_R_OPEN; }

#ifdef CWDEBUG
  // Returns true if this object is used for debug output.
  // If it is, then no new debug output will be produced by the kernel while handling it.
  bool is_debug_channel() const { return m_flags & FDS_DEBUG; }
#endif

 public:
  // (Re)Initialize the Device using filedescriptor fd.
  void init(int fd)
  {
    DoutEntering(dc::io, "IOBase::init(" << fd << ") [" << (void*)this << ']');
    // Only call init() with a valid, open filedescriptor.
    ASSERT(is_valid(fd));

    // Make file descriptor non-blocking by default.
    set_nonblocking(fd);

    // Reset all flags except FDS_RW.
    m_flags &= FDS_RW;
    init_input_device(fd);
    init_output_device(fd);
  }

  void start()
  {
    start_input_device();
    start_output_device();
  }

  // After this call the object might be destructed.
  void stop()
  {
    RefCountReleaser release1 = stop_input_device();
    RefCountReleaser release2 = stop_output_device();
  }

  void disable()
  {
    disable_input_device();
    disable_output_device();
  }

  void enable()
  {
    enable_input_device();
    enable_output_device();
  }

  RefCountReleaser close_fds()
  {
    RefCountReleaser releaser;
    releaser = close_input_device();
    releaser += close_output_device();
    return releaser;
  }
};


//=============================================================================
//
// class InputDevice
//
// Base class for classes that define Input characteristics.
//
// This class implements the following virtual functions of IOBase:
//
// void init_input_device(int fd) override;     // Initializes m_input_watcher and registers fd for reading (calls ev_io_init). Adds FDS_R_OPEN to m_flags.
// int get_input_fd() const override;           // Gets the fd as passed to (the last call to) init_input_device.
// void start_input_device() override;          // Starts watching the fd.
// RefCountReleaser stop_input_device() override;           // Stops watching the fd.
// void disable_input_device() override;        // Adds FDS_R_DISABLED to m_flags and stops watching the fd.
// void enable_input_device() override;         // Removes FDS_R_DISABLED from m_flags and starts watching the fd again.
//
// The following new virtual functions are defined:
//
// virtual void read_from_fd(int fd);           // Called when more data might be available for reading from fd.
//
//   The default implementation calls:
//
//   virtual void read_returned_zero();         // read(fd) returned 0.
//   virtual void read_error(int err);          // read(fd) returned -1 with errno == err (!= EAGAIN or EWOULDBLOCK).
//   virtual void data_received(char const* new_data, size_t rlen);     // rlen (> 0) new bytes have been written to the buffer, contiguously available as new_data.
//
//   If the buffer is full then stop_input_device is called.

class InputDevice : public virtual IOBase
{
 public:
  // The default blocksize for your `StreamBuf' input buffers, used
  // when you don't pass that size to the constructors.
  static size_t constexpr default_blocksize_c = default_input_blocksize_c;

  // Used default posix mode for opening files, when you don't pass it to the constructor.
  static int const mode = std::ios_base::in;

 protected:
  //---------------------------------------------------------------------------
  // The input buffer
  //

  using buffer_type = InputBuffer;
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
  RefCountReleaser stop_input_device() override;
  int get_input_fd() const override;

 protected:
  //---------------------------------------------------------------------------
  // Constructor:
  //
  // Protected: May only be constructed by dbbuf_fd_dtct.
  //
  InputDevice(Dev2Buf* ibuf) : m_ibuffer(static_cast<InputBuffer*>(ibuf))
  {
    DoutEntering(dc::io, "InputDevice(" << (void*)static_cast<StreamBuf*>(ibuf) << ") [" << (void*)static_cast<IOBase*>(this) << ']');
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
    DoutEntering(dc::io, "~InputDevice() [" << (void*)static_cast<IOBase*>(this) << ']');
    // Don't delete a device? At most close() it and delete all boost::intrusive_ptr's to it.
    ASSERT(!is_active());
    if (is_open_r())
      close_input_device();     // This will not delete the object (again) because it isn't active.
    // Delete the input buffer if it is no longer needed.
    m_ibuffer->release(this);
    // Make sure we detect it if this watcher is used again.
    Debug(m_input_watcher.data = nullptr);
  }

  // Disallow copy constructing.
  InputDevice(InputDevice const&) = delete;

 private:
  // The call back used by libev.
  static void s_evio_cb(EV_P_ ev_io* w, int)
  {
    // Release the mutex on 'loop' while calling an external function.
    auto release_lock = EventLoopThread::temporary_release(EV_A);
    static_cast<InputDevice*>(w->data)->read_from_fd(w->fd);
  }

 public:
  //---------------------------------------------------------------------------
  // Public accessors:
  //

  // Supposed to be used for passing it to other device constructors.
  Dev2Buf* rddbbuf() const { return m_ibuffer; }

  // Returns true if our watcher is linked in with libev.
  bool is_active() const { return ev_is_active(&m_input_watcher); }

 public:
  //---------------------------------------------------------------------------
  // Public manipulators:
  //

  void disable_input_device() override
  {
    m_flags |= FDS_R_DISABLED;
    m_disable_release = stop_input_device();
  }

  void enable_input_device() override
  {
    m_flags &= ~FDS_R_DISABLED;
    if (is_readable())
      start_input_device();
    m_disable_release.execute();
  }

  RefCountReleaser close_input_device()
  {
    DoutEntering(dc::io, "InputDevice::close_input_device() [" << this << ']');
    RefCountReleaser releaser;
    int input_fd = m_input_watcher.fd;
    if (AI_LIKELY(is_open_r()))
    {
      bool already_closed = (m_flags & (FDS_SAME | FDS_W_OPEN)) == FDS_SAME;
#ifdef CWDEBUG
      if (!already_closed && !is_valid(input_fd))
        Dout(dc::warning, "Calling InputDevice::close on input device with invalid fd = " << input_fd << ".");
#endif
      releaser = stop_input_device();
      if (!already_closed && !dont_close())
      {
        Dout(dc::io|continued_cf, "close(" << input_fd << ") = ");
        DEBUG_ONLY(int err =) ::close(input_fd);
        Dout(dc::warning(err)|error_cf, "Failed to close filedescriptor " << input_fd);
        Dout(dc::finish, err);
      }
      m_flags &= ~FDS_R_OPEN;
      if (!is_open())
      {
        m_flags |= FDS_DEAD;
        closed();
      }
    }
    return releaser;
  }

  RefCountReleaser close()
  {
    return close_input_device();
  }

 private:
  RefCountReleaser m_disable_release;

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

  // The default behaviour is to close() the filedescriptor.
  virtual RefCountReleaser read_returned_zero() { return close(); }

  // The default behaviour is to close() the filedescriptor.
  virtual RefCountReleaser read_error(int UNUSED_ARG(err)) { return close(); }

  // The default behavior is to do nothing.
  virtual void data_received(char const* UNUSED_ARG(new_data), size_t UNUSED_ARG(rlen)) { }
};


//=============================================================================
//
// class OutputDevice
//
// Base class for classes that define Output characteristics.
//
// This class implements the following virtual functions of IOBase:
//
// void init_output_device(int fd) override;    // Initializes m_output_watcher and registers fd for writing (calls ev_io_init). Adds FDS_W_OPEN to m_flags.
// int get_output_fd() const override;          // Gets the fd as passed to (the last call to) init_output_device.
// void start_output_device() override;         // Starts watching the fd.
// void stop_output_device() override;          // Stops watching the fd.
// void disable_output_device() overrid         // Adds FDS_R_DISABLED to m_flags and stops watching the fd.
// void enable_output_device() override         // Removes FDS_R_DISABLED from m_flags and starts watching the fd again.
//
// The following new virtual functions are defined:
//
// virtual int sync();                          // Called when this is an ostream and it is being flushed.
//
//   The default calls start_output_device() when appropriate.
//
// virtual void write_to_fd(int fd);            // The fd is writable.
//
//   The default writes the buffer to the fd. It may call:
//
//   virtual void write_error(int err);         // write(fd, ...) returned -1 with errno == err (!= EAGAIN or EWOULDBLOCK).

class OutputDevice : public virtual IOBase
{
 public:
  // The default blocksize for your `StreamBuf' output buffers, used
  // when you don't pass that size to the constructors.
  static size_t constexpr default_blocksize_c = default_output_blocksize_c;

  // Used default posix mode for opening files, when you don't pass it to the constructor.
  static int const mode = std::ios_base::out;

 protected:
  //---------------------------------------------------------------------------
  // The output buffer
  //

  using buffer_type = OutputBuffer;
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
  RefCountReleaser stop_output_device() override;
  int get_output_fd() const override;

 protected:
  //---------------------------------------------------------------------------
  // Constructor:
  //
  // Protected: May only be constructed by dbbuf_fd_dtct.
  //
  OutputDevice(Buf2Dev* obuf) : m_obuffer(static_cast<OutputBuffer*>(obuf))
  {
    DoutEntering(dc::io, "OutputDevice(" << (void*)static_cast<StreamBuf*>(obuf) << ") [" << (void*)static_cast<IOBase*>(this) << ']');
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
    DoutEntering(dc::io, "~OutputDevice() [" << (void*)static_cast<IOBase*>(this) << ']');
    // Don't delete a device? At most close() it and delete all boost::intrusive_ptr's to it.
    ASSERT(!is_active());
    if (is_open_w())
      close_output_device();    // This will not delete the object (again) because it isn't active.
    // Delete the output buffer if it is no longer needed.
    m_obuffer->release(this);
    // Make sure we detect it if this watcher is used again.
    Debug(m_output_watcher.data = nullptr);
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

  // Called from the streambuf associated with this device when pubsync() is called on it.
  friend class Buf2Dev;
  virtual int sync();

 private:
  // The call back used by libev.
  static void s_evio_cb(EV_P_ ev_io* w, int)
  {
    // Release the mutex on 'loop' while calling an external function.
    auto release_lock = EventLoopThread::temporary_release(EV_A);
    static_cast<OutputDevice*>(w->data)->write_to_fd(w->fd);
  }

 public:
  //---------------------------------------------------------------------------
  // Public accessors:
  //

  // Supposed to be used for passing it to other device constructors.
  Buf2Dev* rddbbuf() const { return m_obuffer; }

  // Returns true if our watcher is linked in with libev.
  bool is_active() const { return ev_is_active(&m_output_watcher); }

 public:
  //---------------------------------------------------------------------------
  // Public manipulators:
  //

  void disable_output_device() override
  {
    m_flags |= FDS_W_DISABLED;
    m_disable_release = stop_output_device();
  }

  void enable_output_device() override
  {
    m_flags &= ~FDS_W_DISABLED;
    if (is_writable())
      start_output_device();
    m_disable_release.execute();
  }

  void restart_if_non_active()
  {
    // This function should be called only from Buf2Dev::flush, and therefore be an output device.
    ASSERT(writable_type());
    //FIXME: this looks like a race condition. Two different threads can call this function.
    if (is_writable() && !is_active())
      start_output_device();
  }

  RefCountReleaser close_output_device()
  {
    DoutEntering(dc::io, "OutputDevice::close_output_device() [" << this << ']');
    RefCountReleaser releaser;
    int output_fd = m_output_watcher.fd;
    if (AI_LIKELY(is_open_w()))
    {
      bool already_closed = (m_flags & (FDS_SAME | FDS_R_OPEN)) == FDS_SAME;
#ifdef CWDEBUG
      if (!already_closed && !is_valid(output_fd))
        Dout(dc::warning, "Calling OutputDevice::close on output device with invalid fd = " << output_fd << ".");
#endif
      releaser = stop_output_device();
      if (!already_closed && !dont_close())
      {
        Dout(dc::io|continued_cf, "close(" << output_fd << ") = ");
        DEBUG_ONLY(int err =) ::close(output_fd);
        Dout(dc::warning(err)|error_cf, "Failed to close filedescriptor " << output_fd);
        Dout(dc::finish, err);
      }
      m_flags &= ~FDS_W_OPEN;
      if (!is_open())
      {
        m_flags |= FDS_DEAD;
        closed();
      }
    }
    return releaser;
  }

  RefCountReleaser close()
  {
    return close_output_device();
  }

 private:
  RefCountReleaser m_disable_release;
};


//=============================================================================
//
// class InputDeviceStream
//

class InputDeviceStream : public InputDevice, public std::istream
{
 protected:
  using iostream_type = std::istream;
  InputDeviceStream(InputBuffer* ibuf) : InputDevice(ibuf), std::istream(ibuf) { }
};


//=============================================================================
//
// class OutputDeviceStream
//

class OutputDeviceStream : public OutputDevice, public std::ostream
{
 protected:
  using iostream_type = std::ostream;
  OutputDeviceStream(OutputBuffer* obuf) :OutputDevice(obuf), std::ostream(obuf) { }
};


//=============================================================================
//
// class ReadInputDevice
//
// Base class for reading from a device, using a general read(2) implementation.
//
// This class implements the following virtual functions of InputDevice:
//
// void data_received(char const* new_data, size_t rlen);       // Decodes the message once enough has arrived to do so.
//
// The following new virtual functions are defined:
//
// virtual size_t end_of_msg_finder(char const* new_data, size_t rlen);         // Called with newly received data of rlen contiguous bytes.
// virtual void decode(MsgBlock msg);						// Called with a complete (contiguous) message.
//
//   end_of_msg_finder must return the number of bytes of the bytes passed to
//   it that complete the current message, or 0 when there is no complete
//   message yet. The first time it is called new_data points to the very
//   beginning of a new message. If 0 is returned then subsequent calls are
//   to added data. Once a non-zero value is returned, the next call will
//   have new_data point immediately after the previous message and thus
//   at the start of the next message.
//
//   For example, if a message is exactly 64 bytes and the buffer pointer
//   starts at 1000 then the following calls are possible:
//
//   end_of_msg_finder(1000, 40) <-- return 0
//   end_of_msg_finder(1040, 40) <-- return 24
//   end_of_msg_finder(1064, 40) <-- return 0
//   end_of_msg_finder(1104, 20) <-- return 0
//   end_of_msg_finder(1124, 130) <-- return 4
//   end_of_msg_finder(1128, 126) <-- return 64
//   end_of_msg_finder(1192, 62) <-- return 0
//   etc.

class ReadInputDevice : public InputDevice
{
 protected:
  // The pure virtual function end_of_msg_finder(char const*, size_t)
  // is called when new data is received.
  //
  // When end_of_msg_finder returns a value > 0, then the pure virtual
  // function decode is called.
  void data_received(char const* new_data, size_t rlen) override;

  // Returns the size of the first message, or 0 if there is no complete message.
  virtual size_t end_of_msg_finder(char const*, size_t) = 0;

  // Called by the default data_received (see above).
  // Msg is a contiguous message.
  virtual RefCountReleaser decode(MsgBlock msg) = 0;

 protected:
  //---------------------------------------------------------------------------
  // Constructor:
  //

  ReadInputDevice(InputBuffer* ibuf) : InputDevice(ibuf) { }
};


//=============================================================================
//
// class ReadInputDeviceStream
//

class ReadInputDeviceStream : public ReadInputDevice, public std::istream
{
 protected:
  using iostream_type = std::istream;
  ReadInputDeviceStream(InputBuffer* ibuf) : ReadInputDevice(ibuf), std::istream(ibuf) { }
};


//=============================================================================
//
// class LinkInputDevice
//
// Base class which only reads data from its fd and writes it into the buffer.
//

class LinkInputDevice : public InputDevice
{
 public:
  using buffer_type = LinkBuffer;
  using buflink_type = LinkOutputDevice;

 public:
  // Used default posix mode for opening files, when you don't pass it to
  // the constructor.
  static int constexpr mode = std::ios_base::in;

  // The default blocksize for your `StreamBuf' link buffers, used
  // when you don't pass that size to the constructors.
  static size_t constexpr default_blocksize_c = 2048;

 public:
  //---------------------------------------------------------------------------
  // Public accessor:
  //

  // Supposed to be used for passing it to other device constructors.
  Dev2Buf* rddbbuf() const { return m_ibuffer; }

 protected:
  //---------------------------------------------------------------------------
  // Constructor:
  //
  // Protected: May only be constructed by dbbuf_fd_dtct
  //

  LinkInputDevice(LinkBuffer* lbuf) : InputDevice(lbuf) { }

  // Tell the output device that new data is received.
  void data_received(char const* UNUSED_ARG(new_data), size_t UNUSED_ARG(rlen)) override
  {
    static_cast<LinkBuffer*>(static_cast<Dev2Buf*>(m_ibuffer))->flush();
  }
};


//=============================================================================
//
// class WriteOutputDevice
//
// Base class to write to a device, using a default write(2) implementation.
//

class WriteOutputDevice : public OutputDevice
{
 public:
  //---------------------------------------------------------------------------
  // Accessors
  //

 protected:
  //---------------------------------------------------------------------------
  // Constructor:
  //

  WriteOutputDevice(OutputBuffer* obuf) : OutputDevice(obuf) { }
};


//=============================================================================
//
// class WriteOutputDeviceStream
//

class WriteOutputDeviceStream : public WriteOutputDevice, public std::ostream
{
 protected:
  using iostream_type = std::ostream;
  WriteOutputDeviceStream(OutputBuffer* obuf) : WriteOutputDevice(obuf), std::ostream(obuf) { }
};


//=============================================================================
//
// class LinkOutputDevice
//
// Base class which only reads data from its buffer and writes it to the fd.
//

class LinkOutputDevice : public OutputDevice
{
 public:
  using buffer_type = LinkBuffer;
  using buflink_type = LinkInputDevice;

  // Used default posix mode for opening files, when you don't pass it to the constructor.
  static int constexpr mode = std::ios_base::out;

  // The default blocksize for your `StreamBuf' link buffers, used
  // when you don't pass that size to the constructors.
  static size_t constexpr default_blocksize_c = 2048;

 protected:
  //---------------------------------------------------------------------------
  // Constructor:
  //
  // Protected: May only be constructed by dbbuf_fd_dtct
  //

  LinkOutputDevice(LinkBuffer* lbuf) : OutputDevice(lbuf->as_Buf2Dev()) { }
};

template<typename DeviceType, typename... ARGS>
boost::intrusive_ptr<DeviceType> create(ARGS&&... args)
{
  return new DeviceType(std::forward<ARGS>(args)...);
}

} // namespace evio

inline std::ostream& operator<<(std::ostream& os, evio::IOBase* device)
{
  return os << (void*)device;
}
