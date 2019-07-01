// evio -- Event Driven I/O support.
//
//! @file
//! @brief Declaration of FileDescriptor.
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

#include "NAD.h"
#include "utils/AIRefCount.h"
#include "utils/log2.h"
#include "utils/InstanceTracker.h"
#include "utils/AIAlert.h"
#include <cstdint>
#include <atomic>
#include <sys/epoll.h>

#if defined(CWDEBUG) && !defined(DOXYGEN)
NAMESPACE_DEBUG_CHANNELS_START
extern channel_ct evio;
NAMESPACE_DEBUG_CHANNELS_END
#endif

char const* epoll_op_str(int op);
std::ostream& operator<<(std::ostream& os, epoll_event const& event);

namespace evio {

// Return true if fd is a valid open filedescriptor.
bool is_valid(int fd);

class FileDescriptorFlags
{
 public:
  using mask_t = uint64_t;

  // .-FDS_SAME
  // |    .-FDS_DEAD
  // |    |.-INTERNAL_FDS_DONT_CLOSE
  // |    ||.-FDS_DEBUG        <-infer->
  // |    |||                  <--disabled_shft->                       _ epoll_width
  // |    |||                  <--------open_shft-------->             /
  // v    vvv                  <-----------------added_shft-------><------->
  // 10000111 00000000 00000101 00000101 00000101 00000101 00000101 00000101
  //                        ^ ^      ^ ^      ^ ^      ^ ^      ^ ^      ^ ^
  //                        | |      | |      | |      | |      | |      |  \_ FDS_R_ACTIVE = EPOLLIN
  //                        | |      | |      | |      | |      | |       \___ FDS_W_ACTIVE = EPOLLOUT
  //                        | |      | |      | |      | |      | `-FDS_R_ADDED
  //                        | |      | |      | |      | |      `-FDS_W_ADDED
  //                        | |      | |      | |      | `-FDS_R_OPEN
  //                        | |      | |      | |      `-FDS_W_OPEN
  //                        | |      | |      | `-FDS_R_DISABLED
  //                        | |      | |      `-FDS_W_DISABLED
  //                        | |      | `-FDS_R_INFERIOR
  //                        | |      `-FDS_W_INFERIOR
  //                        | `-FDS_R
  //                        `-FDS_W

  static int constexpr epoll_width = utils::log2(EPOLLIN | EPOLLOUT) + 1;
  static int constexpr inferior_shft = epoll_width;
  static int constexpr disabled_shft = 2 * epoll_width;
  static int constexpr open_shft = 3 * epoll_width;
  static int constexpr added_shft = 4 * epoll_width;

  static mask_t constexpr FDS_R_ACTIVE            = EPOLLIN;                    // Set when epoll is using a pointer to this object (is watching this fd for input activity).
  static mask_t constexpr FDS_W_ACTIVE            = EPOLLOUT;                   // Set when epoll is using a pointer to this object (is watching this fd for output activity).

  static int constexpr active_to_type_shft = added_shft + epoll_width;
  static mask_t constexpr FDS_R                   = FDS_R_ACTIVE << active_to_type_shft;
  static mask_t constexpr FDS_W                   = FDS_W_ACTIVE << active_to_type_shft;
  static mask_t constexpr FDS_RW                  = FDS_R | FDS_W;

  static mask_t constexpr FDS_R_ADDED             = FDS_R >> added_shft;
  static mask_t constexpr FDS_W_ADDED             = FDS_W >> added_shft;
  static mask_t constexpr FDS_ADDED               = FDS_R_ADDED | FDS_W_ADDED;
  static int constexpr active_to_added_shft = active_to_type_shft - added_shft;

  static mask_t constexpr FDS_R_OPEN              = FDS_R >> open_shft;         // See is_open() below.
  static mask_t constexpr FDS_W_OPEN              = FDS_W >> open_shft;
  static int constexpr active_to_open_shft = active_to_type_shft - open_shft;

  static mask_t constexpr FDS_R_DISABLED          = FDS_R >> disabled_shft;     // See is_disabled() below.
  static mask_t constexpr FDS_W_DISABLED          = FDS_W >> disabled_shft;
  static int constexpr active_to_disabled_shft = active_to_type_shft - disabled_shft;

  static mask_t constexpr FDS_R_INFERIOR          = FDS_R >> inferior_shft;
  static mask_t constexpr FDS_W_INFERIOR          = FDS_W >> inferior_shft;
  static int constexpr active_to_inferior_shft = active_to_type_shft - inferior_shft;

  static mask_t constexpr FDS_SAME                = 0x8000000000000000UL;
  static mask_t constexpr FDS_REGULAR_FILE        = 0x1000000000000000UL;
  static mask_t constexpr FDS_W_FLUSHING          = 0x0800000000000000UL;
  static mask_t constexpr FDS_DEAD                = 0x0400000000000000UL;
  static mask_t constexpr INTERNAL_FDS_DONT_CLOSE = 0x0200000000000000UL;
  static mask_t constexpr FDS_DEBUG               = 0x0100000000000000UL;
  static_assert(FDS_W < FDS_DEBUG, "epoll_width is too large!");

 private:
  mask_t m_mask;

 public:
  // Return true if this object is a base class of OutputDevice.
  bool is_output_device() const { return m_mask & FDS_W; }

  // Return true if this object is a base class of InputDevice.
  bool is_input_device() const { return m_mask & FDS_R; }

  // Return true if this object is a evio::File.
  bool is_regular_file() const { return m_mask & FDS_REGULAR_FILE; }

  // Returns true if this object is a writable device.
  bool is_writable() const { return (m_mask & (FDS_W|FDS_W_DISABLED|FDS_W_OPEN|FDS_DEAD)) == (FDS_W|FDS_W_OPEN); }

  // Returns true if this object is a readable device.
  bool is_readable() const { return (m_mask & (FDS_R|FDS_R_DISABLED|FDS_R_OPEN|FDS_DEAD)) == (FDS_R|FDS_R_OPEN); }

  // Return true if this object is marked that it should not close its fd.
  bool dont_close() const { return m_mask & INTERNAL_FDS_DONT_CLOSE; }

  // Return true if this object has an open filedescriptor.
  bool is_open() const { return m_mask & ((m_mask & FDS_RW) >> open_shft); }

  // Return true if this object is marked as having an open fd for writing.
  bool is_w_open() const { return m_mask & FDS_W_OPEN; }

  // Return true if this object is marked as having an open fd for reading.
  bool is_r_open() const { return m_mask & FDS_R_OPEN; }

  // Return true if the main event loop must return even when this input device is still active.
  bool is_w_inferior() const { return m_mask & FDS_W_INFERIOR; }

  // Return true if the main event loop must return even when this input device is still active.
  bool is_r_inferior() const { return m_mask & FDS_R_INFERIOR; }

  // Return true if this output device is 'flushing'.
  bool is_w_flushing() const { return m_mask & FDS_W_FLUSHING; }

  // Return true if this object is inferior for the action passed in active_flag.
  bool test_inferior(mask_t active_flag) const { return m_mask & (active_flag << active_to_inferior_shft); }

  // Returns true if this object is not associated with a working fd.
  bool is_dead() const { return m_mask & FDS_DEAD; }

  // Returns true if this object is disabled at this moment.
  bool is_disabled() const { return m_mask & ((m_mask & FDS_RW) >> disabled_shft); }

  // Return true if this object is disabled fro writing.
  bool is_w_disabled() const { return m_mask & FDS_W_DISABLED; }

  // Return true if this object is disabled for reading.
  bool is_r_disabled() const { return m_mask & FDS_R_DISABLED; }

  // Return true if this object is disabled for the action passed in active_flag.
  bool test_disabled(mask_t active_flag) const { return m_mask & (active_flag << active_to_disabled_shft); }

  // Return true if this object is added to the kernel epoll structure because it is an input device.
  bool is_r_added() const { return m_mask & FDS_R_ADDED; }

  // Return true if this object is added to the kernel epoll structure because it is an output device.
  bool is_w_added() const { return m_mask & FDS_W_ADDED; }

  // Return true if this object was added to the kernel epoll structure.
  bool is_added() const { return m_mask & FDS_ADDED; }

  // Returns true if this object is being watched for writability.
  bool is_active_output_device() const { return m_mask & FDS_W_ACTIVE; }

  // Returns true if this object is being watched for readability.
  bool is_active_input_device() const { return m_mask & FDS_R_ACTIVE; }

  // Return true if this object has or had a fd that is open for both reading and writing.
  bool is_same() const { return m_mask & FDS_SAME; }

#ifdef CWDEBUG
  // Returns true if this object is used for debug output.
  // If it is, then no new debug output will be produced by the kernel while handling it.
  bool is_debug_channel() const { return m_mask & FDS_DEBUG; }
#endif

  // Reset all flags except FDS_RW and FDS_REGULAR_FILE.
  void reset() { m_mask &= FDS_RW | FDS_REGULAR_FILE; }

  // Mark this object as being derived from OutputDevice.
  void set_output_device() { m_mask |= FDS_W; }

  // Mark this object as being derived from InputDevice.
  void set_input_device() { m_mask |= FDS_R; }

  // Mark this object as being derived from File.
  void set_regular_file() { m_mask |= FDS_REGULAR_FILE; }

  // Set the FDS_W_DISABLED flag.
  void set_w_disabled() { m_mask |= FDS_W_DISABLED; }

  // Set the FDS_R_DISABLED flag.
  void set_r_disabled() { m_mask |= FDS_R_DISABLED; }

  // Reset the FDS_W_DISABLED flag.
  void unset_w_disabled() { m_mask &= ~FDS_W_DISABLED; }

  // Reset the FDS_R_DISABLED flag.
  void unset_r_disabled() { m_mask &= ~FDS_R_DISABLED; }

  // Set the INTERNAL_FDS_DONT_CLOSE flag.
  void set_dont_close() { m_mask |= INTERNAL_FDS_DONT_CLOSE; }

  // Mark this object as having a fd open for writing.
  void set_w_open()
  {
    m_mask |= FDS_W_OPEN;
    // Keep track of whether or not there is an input device (that will have the same fd).
    if ((m_mask & FDS_R_OPEN))
      m_mask |= FDS_SAME;
  }

  // Mark this object as having its (write) fd closed.
  void unset_w_open() { m_mask &= ~FDS_W_OPEN; }

  // Mark this object as having a fd open for reading.
  void set_r_open()
  {
    m_mask |= FDS_R_OPEN;
    // Keep track of whether or not there is an output device (that will have the same fd).
    if ((m_mask & FDS_W_OPEN))
      m_mask |= FDS_SAME;
  }

  // Mark this object as having its (read) fd closed.
  void unset_r_open() { m_mask &= ~FDS_R_OPEN; }

  // Mark this device as inferior input; that is - the appliction will terminate even if this input device is still active.
  void set_r_inferior() { m_mask |= FDS_R_INFERIOR; }

  // Mark this device as flushing: the next call to stop_output_device() will have the same effect as close_output_device().
  void set_w_flushing() { m_mask |= FDS_W_FLUSHING; }

  // Remove the flushing flag.
  void unset_w_flushing() { m_mask &= ~FDS_W_FLUSHING; }

  // Mark this object as dead.
  void set_dead() { m_mask |= FDS_DEAD; }

  // Return true iff the device was active. Clears active flag.
  bool test_and_clear_active(mask_t active_flag)
  {
    ASSERT(active_flag == FDS_R_ACTIVE || active_flag == FDS_W_ACTIVE);
    mask_t prev_mask = m_mask;
    mask_t need_change = prev_mask & active_flag;
    m_mask = prev_mask ^ need_change;
    return need_change;
  }

  void set_active(mask_t active_flag)
  {
    ASSERT(active_flag == FDS_R_ACTIVE || active_flag == FDS_W_ACTIVE);
    m_mask |= active_flag;
  }

  void clear_active(mask_t active_flag)
  {
    m_mask &= ~active_flag;
  }

  bool test_and_set_active(mask_t active_flag)
  {
    ASSERT(active_flag == FDS_R_ACTIVE || active_flag == FDS_W_ACTIVE);
    mask_t prev_mask = m_mask;
    mask_t need_change = ~prev_mask & active_flag;
    m_mask = prev_mask | need_change;
    return need_change;
  }

  // Clear the ADDED flag; return true on change (aka, originally the flag was set).
  bool test_and_clear_added(mask_t active_flag)
  {
    ASSERT(active_flag == FDS_R_ACTIVE || active_flag == FDS_W_ACTIVE);
    mask_t added_flag = active_flag << active_to_added_shft;
    bool was_added = m_mask & FDS_ADDED;
    m_mask &= ~added_flag;
    return was_added;
  }

  // Set the ADDED flag; return true on change (aka, originally the flag was unset).
  bool test_and_set_added(mask_t active_flag)
  {
    ASSERT(active_flag == FDS_R_ACTIVE || active_flag == FDS_W_ACTIVE);
    mask_t added_flag = active_flag << active_to_added_shft;
    bool already_added = m_mask & FDS_ADDED;
    m_mask |= added_flag;
    return !already_added;
  }

  FileDescriptorFlags() : m_mask(0) { }

  friend std::ostream& operator<<(std::ostream& os, FileDescriptorFlags const& flags);
};

class FileDescriptor : public AIRefCount, public utils::InstanceTracker<FileDescriptor>
{
 public:
  struct State
  {
    FileDescriptorFlags m_flags;
    struct epoll_event m_epoll_event;
  };
  using state_t = aithreadsafe::Wrapper<State, aithreadsafe::policy::Primitive<std::mutex>>;

 protected:
  state_t m_state;
  int m_fd;                           // The file descriptor. In the case of a device that is derived from both,
                                      // InputDevice and OutputDevice using multiple inheritance -- this fd is
                                      // used for both input and output.

  // (Re)Initialize the Device using filedescriptor fd.
  void init(int fd);

#ifdef CWDEBUG
  // For inspection only.
  int get_fd() const { return m_fd; }
  FileDescriptorFlags const get_flags() const { return state_t::crat(m_state)->m_flags; }
#endif

 public:
  void start_watching(FileDescriptor::state_t::wat const& state_w, int epoll_fd, uint32_t events, bool needs_adding)
  {
    state_w->m_epoll_event.events |= events;
    int op = needs_adding ? EPOLL_CTL_ADD : EPOLL_CTL_MOD;
    Dout(dc::system|continued_cf, "epoll_ctl(" << epoll_fd << ", " << epoll_op_str(op) << ", " << m_fd << ", {" << state_w->m_epoll_event << "}) = ");
    DEBUG_ONLY(int ret =) epoll_ctl(epoll_fd, op, m_fd, &state_w->m_epoll_event);
    Dout(dc::finish|cond_error_cf(ret == -1), ret);
    // If epoll_fd == -1 and errno EBADF: did you create an EventLoop object at the start of main?
    // Assuming errno is EPERM, then this device doesn't support epoll. Call set_regular_file() on it.
    ASSERT(ret != -1);
  }

  void stop_watching(FileDescriptor::state_t::wat const& state_w, int epoll_fd, uint32_t events, bool needs_removal)
  {
    state_w->m_epoll_event.events &= ~events;
    int op = needs_removal ? EPOLL_CTL_DEL : EPOLL_CTL_MOD;
    Dout(dc::system|continued_cf, "epoll_ctl(" << epoll_fd << ", " << epoll_op_str(op) << ", " << m_fd << ", {" << state_w->m_epoll_event << "}) = ");
    int ret = epoll_ctl(epoll_fd, op, m_fd, &state_w->m_epoll_event);
    Dout(dc::finish|cond_error_cf(ret == -1), ret);
    if (AI_UNLIKELY(ret == -1))
    {
      // This is an unrecoverable error... Application should print this information and terminate.
      THROW_FALERTE("epoll_ctl([EPOLL_FD], [EPOLL_OP_STR], [FD], [EPOLL_EVENT]) = -1",
          AIArgs("[EPOLL_FD]", epoll_fd)("[EPOLL_OP_STR]", epoll_op_str(op))("[FD]", m_fd)("[EPOLL_EVENT]", state_w->m_epoll_event));
    }
  }

 private:
  // These are called from EventLoopThread::main().
  friend class EventLoopThread;
  virtual NAD_DECL_UNUSED_ARG(read_event) { DoutFatal(dc::core, "Calling FileDescriptor::read_event() on object that isn't an InputDevice."); }
  virtual NAD_DECL_UNUSED_ARG(write_event) { DoutFatal(dc::core, "Calling FileDescriptor::write_event() on object that isn't an OutputDevice."); }
  virtual NAD_DECL_UNUSED_ARG(hup_event) { Dout(dc::warning, "Calling FileDescriptor::hup_event() on object that isn't an InputDevice."); }
  virtual NAD_DECL_UNUSED_ARG(exceptional_event) { Dout(dc::warning, "Calling FileDescriptor::exceptional_event() on object that isn't an InputDevice."); }

 private:
  // At least one of these must be overridden to initialize the appropriate device(s).
  // Both are called by init().
  virtual void init_input_device(state_t::wat const& UNUSED_ARG(state_w)) { }
  virtual void init_output_device(state_t::wat const& UNUSED_ARG(state_w)) { }

 protected:
  FileDescriptor() : m_fd(-1) { state_t::wat state_w(m_state); state_w->m_epoll_event = {0, {this}}; }
  ~FileDescriptor() noexcept { }

  // Called by close(). These will be overridden by InputDevice and/or OutputDevice.
  virtual NAD_DECL_UNUSED_ARG(close_input_device) { }
  virtual NAD_DECL_UNUSED_ARG(close_output_device) { }

 public:
  NAD_DECL_PUBLIC(close_input_device)
  {
    NAD_PUBLIC_BEGIN;
    NAD_CALL_FROM_PUBLIC(close_input_device);
    NAD_PUBLIC_END;
  }

  NAD_DECL_PUBLIC(close_output_device)
  {
    NAD_PUBLIC_BEGIN;
    NAD_CALL_FROM_PUBLIC(close_output_device);
    NAD_PUBLIC_END;
  }

  NAD_DECL_PUBLIC(close)
  {
    NAD_PUBLIC_BEGIN;
    NAD_CALL_PUBLIC(close_input_device);
    NAD_CALL_PUBLIC(close_output_device);
    NAD_PUBLIC_END;
  }

  // Overload for internal (non-public) call.
  NAD_DECL(close)
  {
    NAD_CALL(close_input_device);
    NAD_CALL(close_output_device);
  }

 protected:
  // Events.
  // The filedescriptor of this device was just closed.
  // If INTERNAL_FDS_DONT_CLOSE is set then the fd wasn't really closed, but this method is still called.
  // When we get here the object is also marked as FDS_DEAD.
  virtual NAD_DECL_UNUSED_ARG(closed) { }

#ifdef CWDEBUG
  friend std::ostream& operator<<(std::ostream& os, FileDescriptor const* fdptr)
  {
    return os << "FD:" << static_cast<void const*>(fdptr);
  }
#endif
};

std::ostream& operator<<(std::ostream& os, FileDescriptor::State const& state);

// Convenience function to create devices.
template<typename DeviceType, typename... ARGS, typename = typename std::enable_if<std::is_base_of<FileDescriptor, DeviceType>::value>::type>
boost::intrusive_ptr<DeviceType> create(ARGS&&... args)
{
#ifdef CWDEBUG
  LibcwDoutScopeBegin(LIBCWD_DEBUGCHANNELS, ::libcwd::libcw_do, dc::evio)
  LibcwDoutStream << "Entering evio::create<" << libcwd::type_info_of<DeviceType>().demangled_name();
  (LibcwDoutStream << ... << (", " + libcwd::type_info_of<ARGS>().demangled_name())) << ">(" << join(", ", args...) << ')';
  LibcwDoutScopeEnd;
  ::NAMESPACE_DEBUG::Indent indentation(2);
#endif
  DeviceType* device = new DeviceType(std::forward<ARGS>(args)...);
  AllocTag2(device, "Created with evio::create");
  Dout(dc::evio, "Returning device pointer " << (void*)device << " [" << static_cast<FileDescriptor*>(device) << "].");
  return device;
}

} // namespace evio
