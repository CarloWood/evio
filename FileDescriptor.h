/**
 * evio -- A cwm4 git submodule for adding support for buffered, iostream oriented, epoll based I/O.
 *
 * @file
 * @brief Declaration of FileDescriptor.
 *
 * @Copyright (C) 2018  Carlo Wood.
 *
 * RSA-1024 0x624ACAD5 1997-01-26                    Sign & Encrypt
 * Fingerprint16 = 32 EC A7 B6 AC DB 65 A6  F6 F6 55 DD 1C DC FF 61
 *
 * This file is part of evio.
 *
 * Evio is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Evio is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with evio.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef EVIO_FILEDESCRIPTOR_H
#define EVIO_FILEDESCRIPTOR_H

#include "RefCountReleaser.h"
#include "utils/AIRefCount.h"
#include "utils/log2.h"
#include "utils/InstanceTracker.h"
#include "utils/AIAlert.h"
#if CW_DEBUG
#include "utils/is_power_of_two.h"
#endif
#include <cstdint>
#include <atomic>
#include <new>
#include <sys/epoll.h>

#if defined(CWDEBUG) && !defined(DOXYGEN)
NAMESPACE_DEBUG_CHANNELS_START
extern channel_ct evio;
NAMESPACE_DEBUG_CHANNELS_END
#endif

char const* epoll_op_str(int op);
std::string epoll_events_str(uint32_t events);
std::ostream& operator<<(std::ostream& os, epoll_event const& event);

namespace evio {

// Return true if fd is a valid open filedescriptor.
bool is_valid(int fd);

class FileDescriptorFlags
{
 public:
  using mask_t = uint64_t;

  // .-FDS_SAME
  // | .-FDS_REGULAR_FILE
  // | |.-FDS_W_CLOSE
  // | ||.-FDS_W_FLUSHING
  // | |||.-FDS_DEAD
  // | ||||.-INTERNAL_FDS_DONT_CLOSE
  // | |||||.-FDS_DEBUG                       inferior_shft
  // | ||||||                                /    disabled_shft
  // | ||||||                             <---->   /
  // | ||||||                             <---------->                      _ epoll_width
  // | ||||||                             <----open_shft--->               /
  // v vvvvvv                             <------added_shft------>      <---->
  // 10111111 0000000000000000000000 00101 00101 00101 00101 00101 00101 11101
  //                                   ^ ^   ^ ^   ^ ^   ^ ^   ^ ^   ^ ^ ^^^ ^
  //                                   | |   | |   | |   | |   | |   | | |||  \_ FDS_EPOLLIN_BUSY = EPOLLIN
  //                                   | |   | |   | |   | |   | |   | | || \___ FDS_EPOLLOUT_BUSY = EPOLLOUT
  //                                   | |   | |   | |   | |   | |   | | |\_____ FDS_EPOLLERR_BUSY = EPOLLERR
  //                                   | |   | |   | |   | |   | |   | | \______ FDS_EPOLLHUP_BUSY = EPOLLHUP
  //                                   | |   | |   | |   | |   | |   | `-FDS_R_ACTIVE
  //                                   | |   | |   | |   | |   | |   `---FDS_W_ACTIVE
  //                                   | |   | |   | |   | |   | `-FDS_R_ADDED
  //                                   | |   | |   | |   | |   `-FDS_W_ADDED
  //                                   | |   | |   | |   | `-FDS_R_OPEN
  //                                   | |   | |   | |   `-FDS_W_OPEN
  //                                   | |   | |   | `-FDS_R_DISABLED
  //                                   | |   | |   `-FDS_W_DISABLED
  //                                   | |   | `-FDS_R_INFERIOR
  //                                   | |   `-FDS_W_INFERIOR
  //                                   | `-FDS_R
  //                                   `-FDS_W

  static int constexpr epoll_width = utils::log2(EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP) + 1;
  static int constexpr inferior_shft = epoll_width;
  static int constexpr disabled_shft = 2 * epoll_width;
  static int constexpr open_shft = 3 * epoll_width;
  static int constexpr added_shft = 4 * epoll_width;
  static int constexpr active_to_type_shft = 5 * epoll_width;

  static mask_t constexpr FDS_EPOLLIN_BUSY        = EPOLLIN;
  static mask_t constexpr FDS_EPOLLOUT_BUSY       = EPOLLOUT;
  static mask_t constexpr FDS_EPOLLERR_BUSY       = EPOLLERR;
  static mask_t constexpr FDS_EPOLLHUP_BUSY       = EPOLLHUP;

  static mask_t constexpr FDS_R_ACTIVE            = EPOLLIN << epoll_width;     // Set when epoll is using a pointer to this object (is watching this fd for input activity).
  static mask_t constexpr FDS_W_ACTIVE            = EPOLLOUT << epoll_width;    // Set when epoll is using a pointer to this object (is watching this fd for output activity).

  static mask_t constexpr FDS_R                   = FDS_R_ACTIVE << active_to_type_shft;        // See is_input_device() below.
  static mask_t constexpr FDS_W                   = FDS_W_ACTIVE << active_to_type_shft;        // See is_output_device() below.
  static mask_t constexpr FDS_RW                  = FDS_R | FDS_W;

  static mask_t constexpr FDS_R_ADDED             = FDS_R >> added_shft;        // See is_r_added() below.
  static mask_t constexpr FDS_W_ADDED             = FDS_W >> added_shft;        // See is_w_added() below.
  static mask_t constexpr FDS_ADDED               = FDS_R_ADDED | FDS_W_ADDED;
  static int constexpr active_to_added_shft = active_to_type_shft - added_shft;

  static mask_t constexpr FDS_R_OPEN              = FDS_R >> open_shft;         // See is_open() below.
  static mask_t constexpr FDS_W_OPEN              = FDS_W >> open_shft;
  static int constexpr active_to_open_shft = active_to_type_shft - open_shft;

  static mask_t constexpr FDS_R_DISABLED          = FDS_R >> disabled_shft;     // See is_disabled() below.
  static mask_t constexpr FDS_W_DISABLED          = FDS_W >> disabled_shft;
  static int constexpr active_to_disabled_shft = active_to_type_shft - disabled_shft;

  static mask_t constexpr FDS_R_INFERIOR          = FDS_R >> inferior_shft;     // See is_r_inferior() below.
  static mask_t constexpr FDS_W_INFERIOR          = FDS_W >> inferior_shft;     // See is_w_inferior() below.
  static int constexpr active_to_inferior_shft = active_to_type_shft - inferior_shft;

  static mask_t constexpr FDS_SAME                = 0x8000000000000000UL;       // See is_same() below.
  static mask_t constexpr FDS_REGULAR_FILE        = 0x2000000000000000UL;       // See is_regular_file() below.
  static mask_t constexpr FDS_W_CLOSE             = 0x1000000000000000UL;       // See is_w_close() below.
  static mask_t constexpr FDS_W_FLUSHING          = 0x0800000000000000UL;       // See set_w_flushing() below.
  static mask_t constexpr FDS_DEAD                = 0x0400000000000000UL;       // See is_dead() below.
  static mask_t constexpr INTERNAL_FDS_DONT_CLOSE = 0x0200000000000000UL;       // See dont_close() and close() below.
  static mask_t constexpr FDS_DEBUG               = 0x0100000000000000UL;
  static_assert(FDS_W < FDS_DEBUG, "epoll_width is too large!");

 private:
  mask_t m_mask;

 public:
  [[gnu::always_inline]] static uint32_t active_to_events(mask_t active_flag) { return active_flag >> epoll_width; }
  [[gnu::always_inline]] static mask_t event_to_active(uint32_t event) { return event << epoll_width; }

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

  // Return true if the main event loop must return even when this output device is still active.
  bool is_w_inferior() const { return m_mask & FDS_W_INFERIOR; }

  // Return true if the main event loop must return even when this input device is still active.
  bool is_r_inferior() const { return m_mask & FDS_R_INFERIOR; }

  // Return true if this output device is 'flushing'.
  bool is_w_flushing() const { return m_mask & FDS_W_FLUSHING; }

  // Return true if this output device should be automatically, forcefully closed upon leaving the main event loop.
  bool is_w_close() const { return m_mask & FDS_W_CLOSE; }

  // Return true if this object is inferior for the action passed in active_flag.
  bool test_inferior(mask_t active_flag) const
  {
    ASSERT(active_flag == FDS_R_ACTIVE || active_flag == FDS_W_ACTIVE);
    return m_mask & (active_flag << active_to_inferior_shft);
  }

  // Returns true if this object is not associated with a working fd.
  bool is_dead() const { return m_mask & FDS_DEAD; }

  // Returns true if this object is disabled at this moment.
  bool is_disabled() const { return m_mask & ((m_mask & FDS_RW) >> disabled_shft); }

  // Return true if this object is disabled fro writing.
  bool is_w_disabled() const { return m_mask & FDS_W_DISABLED; }

  // Return true if this object is disabled for reading.
  bool is_r_disabled() const { return m_mask & FDS_R_DISABLED; }

  // Return true if this object is disabled for the action passed in active_flag.
  bool test_disabled(mask_t active_flag) const
  {
    ASSERT(active_flag == FDS_R_ACTIVE || active_flag == FDS_W_ACTIVE);
    return m_mask & (active_flag << active_to_disabled_shft);
  }

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

  // Returns true if this object has queued or is handling a read_event in the thread pool.
  bool is_r_busy() const { return m_mask & FDS_EPOLLIN_BUSY; }

  // Returns true if this object has queued or is handling a write_event in the thread pool.
  bool is_w_busy() const { return m_mask & FDS_EPOLLOUT_BUSY; }

#if 0
  // Returns true if this object has queued or is handling either a read_event or write_event in the thread pool.
  bool is_busy() const { return m_mask & (FDS_EPOLLIN_BUSY|FDS_EPOLLOUT_BUSY); }
#endif

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

  // Call close_output_device() when leaving the main event loop.
  // Do not call this function directly! Call OutputDevice::close_on_exit() instead.
  void set_w_close() { m_mask |= FDS_W_CLOSE; }

  // Do not call this function directly! Call OutputDevice::close_on_exit(false) instead.
  void unset_w_close() { m_mask &= ~FDS_W_CLOSE; }

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
    ASSERT(active_flag == FDS_R_ACTIVE || active_flag == FDS_W_ACTIVE);
    m_mask &= ~active_flag;
  }

#if 0
  void clear_busy(mask_t events)
  {
    ASSERT((events & ~(EPOLLIN|EPOLLOUT|EPOLLERR|EPOLLHUP)) == 0);
    m_mask &= ~events;
  }
#endif

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
    // Regular files should never be added to the kernel epoll structure.
    ASSERT(!(m_mask & FDS_REGULAR_FILE));
    mask_t added_flag = active_flag << active_to_added_shft;
    bool already_added = m_mask & FDS_ADDED;
    m_mask |= added_flag;
    return !already_added;
  }

#if 0
  uint32_t test_and_set_busy(uint32_t events)
  {
    mask_t requested_busy_flags = events & (EPOLLIN|EPOLLOUT|EPOLLERR|EPOLLHUP);
    mask_t already_busy = m_mask & requested_busy_flags;
    m_mask |= requested_busy_flags;
    return events ^ already_busy;
  }
#endif

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

  // Overload intrusive_ptr_release for FileDescriptor (as opposed to AIRefCount).
  // This is a bit dangerous: make sure you never cast a FileDescriptor to an AIRefCount.
  friend void intrusive_ptr_release(FileDescriptor const* ptr);
  void allow_deletion(int count) const;

 protected:
  alignas(config::cacheline_size_c) state_t m_state;    // Mutex protected state of this FileDescriptor.
  int m_fd;                                             // The file descriptor. In the case of a device that is derived from both,
                                                        // InputDevice and OutputDevice using multiple inheritance -- this fd is
                                                        // used for both input and output.
  mutable FileDescriptor const* m_next_needs_deletion;  // A singly linked list of FileDescriptor (derived) objects that need to be deleted by the EventLoopThead.
                                                        // Only valid when this object is added to the list itself (EventLoopThread::m_needs_deletion_list).
  alignas(config::cacheline_size_c) std::atomic<uint32_t> m_pending_events;     // Mask of events being handled by the thread pool.

  // (Re)Initialize the Device using filedescriptor fd.
  // make_fd_non_blocking should be true except when the fd is a standard stream (i.e. fd <= 2) or fd is a regular file
  // (or when you are sure that the fd is already non-blocking).
  // The best way to represent a standard stream is therefore with an evio::File.
  virtual void fd_init(int fd, bool make_fd_non_blocking = true);

#if CW_DEBUG
 public:
  // For inspection only.
  FileDescriptorFlags const get_flags() const { return state_t::crat(m_state)->m_flags; }
#endif

 public:
  // This is called by the EventLoopThread to see if an event that was just returned by epoll_pwait()
  // is still (in the thread pool queue or) being processed by a thread.
  //
  // If one or two threads are handling EPOLLIN and/or EPOLLOUT still then we want
  // to suppress any EPOLLHUP and/or EPOLLERR event too, but that is being handled
  // in EventLoopThread::main.
  //
  // Adds the events to m_pending_events.
  // Returns the events that are already being processed by thread pool.
  uint32_t test_and_set_pending_events(uint32_t events)
  {
    // events is what is returned by epoll_pwait and should only contain one or more of these four events.
    ASSERT((events & ~(EPOLLIN | EPOLLOUT | EPOLLHUP | EPOLLERR)) == 0);

    uint32_t prev_busy = m_pending_events.load(std::memory_order_relaxed);

    // We fast-track the case where this function is called many times with the same events,
    // because although it is possible that after reading the value of m_pending_events
    // bits in it get reset by another thread. We can still assume that the load() was the
    // fetch_or (which is a non-op when events == m_pending_events).
    if (AI_LIKELY((prev_busy & events) == events))      // In this case the fetch_or is non-OP.
      return events;

    if (prev_busy == 0)
    {
      // This is the only thread that sets bits m_pending_events.
      // Therefore if that value is zero then it will stay zero and we can avoid the RMW.
      m_pending_events.store(events, std::memory_order_relaxed);
      return 0;
    }

    // Relaxed because this adds event bits and we're only interested to stop this
    // thread from calling this function again and then getting back those events.
    return m_pending_events.fetch_or(events, std::memory_order_relaxed);
  }

  bool is_pending_events(uint32_t event)
  {
    // This is expected to be a single event (active_flag).
    ASSERT(utils::is_power_of_two(event));
    return (m_pending_events.load(std::memory_order_relaxed) & event);
  }

  void do_epoll_ctl(FileDescriptor::state_t::wat const& state_w, int epoll_fd, int op)
  {
    Dout(dc::system|continued_cf, "epoll_ctl(" << epoll_fd << ", " << epoll_op_str(op) << ", " << m_fd << ", {" << state_w->m_epoll_event << "}) = ");
    int ret = epoll_ctl(epoll_fd, op, m_fd, &state_w->m_epoll_event);
    Dout(dc::finish|cond_error_cf(ret == -1), ret);
    // If epoll_fd == -1 and errno EBADF: did you create an EventLoop object at the start of main?
    // Assuming errno is EPERM, then this device doesn't support epoll. Call set_regular_file() on it.
    if (AI_UNLIKELY(ret == -1))
    {
      // This is an unrecoverable error... Application should print this information and terminate.
      THROW_FALERTE("epoll_ctl([EPOLL_FD], [EPOLL_OP_STR], [FD], [EPOLL_EVENT]) = -1",
          AIArgs("[EPOLL_FD]", epoll_fd)("[EPOLL_OP_STR]", epoll_op_str(op))("[FD]", m_fd)("[EPOLL_EVENT]", state_w->m_epoll_event));
    }
  }

  void clear_pending_events(uint32_t events)
  {
    DoutEntering(dc::evio, "FileDescriptor::clear_pending_events(" << epoll_events_str(events) << ") [" << this << "]");
    m_pending_events.fetch_and(~events, std::memory_order_release);
  }

  void clear_pending_input_event(int epoll_fd)
  {
    DoutEntering(dc::evio, "FileDescriptor::clear_pending_input_event(" << epoll_fd << ") [" << this << "]");
    m_pending_events.fetch_and(~EPOLLIN, std::memory_order_release);

    // Rearm fd/event if the current event is still interesting.
    {
      FileDescriptor::state_t::wat state_w(m_state);
      if ((state_w->m_epoll_event.events & EPOLLIN))
      {
        // Rearm fd.
        do_epoll_ctl(state_w, epoll_fd, EPOLL_CTL_MOD);
      }
    }
  }

  // This is called by an AIThreadPool thread after it processed an event.
  // Returns new events that need to be handled by this thread.
  void clear_pending_output_events(int epoll_fd, uint32_t& events)
  {
    DoutEntering(dc::evio|continued_cf, "FileDescriptor::clear_pending_output_events(" << epoll_fd << ", " << epoll_events_str(events) << ") [" << this << "] returning new events: ");

    // Allow a new events to be added to the thread pool for this fd/event.
    // Clear the just handled event(s) and get any pending error events.
    events = m_pending_events.fetch_and(~events, std::memory_order_release) & ~(events | EPOLLIN | EPOLLOUT);

    // Were there any EPOLLHUP and/or EPOLLERR events ignored in the meantime?
    if (AI_UNLIKELY(events))
    {
      Dout(dc::finish, epoll_events_str(events));
      // Handle those events in the same thread.
      return;
    }

    // Rearm fd/event if EPOLLOUT is still interesting.
    {
      FileDescriptor::state_t::wat state_w(m_state);
      if ((state_w->m_epoll_event.events & EPOLLOUT))
      {
        // Rearm fd.
        do_epoll_ctl(state_w, epoll_fd, EPOLL_CTL_MOD);
      }
    }

    Dout(dc::finish, "none");
  }

  void start_watching(FileDescriptor::state_t::wat const& state_w, int epoll_fd, uint32_t event, bool needs_adding)
  {
    state_w->m_epoll_event.events |= event | EPOLLET;
    int op = needs_adding ? EPOLL_CTL_ADD : EPOLL_CTL_MOD;
#if 0
    if (AI_LIKELY(is_pending_events(event)))
      Dout(dc::notice, "Delaying addition of event " << epoll_events_str(event) << " with epoll_ctl [" << this << "]");
    else
#endif
    do_epoll_ctl(state_w, epoll_fd, op);
  }

  void stop_watching(FileDescriptor::state_t::wat const& state_w, int epoll_fd, uint32_t event, bool needs_removal)
  {
    state_w->m_epoll_event.events &= ~event;
    int op = needs_removal ? EPOLL_CTL_DEL : EPOLL_CTL_MOD;
    // It doesn't make sense to rearm a fd when the corresponding event is going to ignored anyway,
    // but we can remove a fd from the epoll interest list, or stop watching events, immediately
    // because the delay is really only to make sure we get an event (using the fact that an epoll_ctl
    // rearms the fd).
    do_epoll_ctl(state_w, epoll_fd, op);
  }

 private:
  // These are called from EventLoopThread::main().
  friend class EventLoopThread;
  void read_event(int& allow_deletion_count) { read_from_fd(allow_deletion_count, m_fd); }
  void write_event(int& allow_deletion_count) { write_to_fd(allow_deletion_count, m_fd); }
  void hup_event(int& allow_deletion_count) { hup(allow_deletion_count, m_fd); }
  void err_event(int& allow_deletion_count) { err(allow_deletion_count, m_fd); }

 public:
  // Used by the testsuite.
  bool is_busy() const
  {
    Dout(dc::notice, m_pending_events);
    return m_pending_events;
  }

 private:
  // At least one of these must be overridden to initialize the appropriate device(s).
  // Both are called by init().
  virtual void init_input_device(state_t::wat const& UNUSED_ARG(state_w)) { }
  virtual void init_output_device(state_t::wat const& UNUSED_ARG(state_w)) { }

 protected:
  FileDescriptor() : m_fd(-1), m_pending_events(0) { state_t::wat state_w(m_state); state_w->m_epoll_event = {0, {this}}; }
  virtual ~FileDescriptor() { }

 protected:
#ifdef CWDEBUG
  friend std::ostream& operator<<(std::ostream& os, FileDescriptor const* fdptr)
  {
    return os << "FD:" << static_cast<void const*>(fdptr);
  }
#endif

 protected:
  virtual void read_from_fd(int& UNUSED_ARG(allow_deletion_count), int UNUSED_ARG(fd))
  {
    ASSERT(!is_destructed());
    // A class derived directly from RawInputDevice must override this method.
    DoutFatal(dc::core, "Calling FileDescriptor::read_read_fd() on object [" << this << "] that isn't an InputDevice.");
  }

  virtual void write_to_fd(int& UNUSED_ARG(allow_deletion_count), int UNUSED_ARG(fd))
  {
    ASSERT(!is_destructed());
    // A class derived directly from RawOutputDevice must override this method.
    DoutFatal(dc::core, "Calling FileDescriptor::write_to_fd() on object [" << this << "] that isn't an OutputDevice.");
  }

#ifdef CWDEBUG
 public:
  // Used for debug code.
#endif
  // Reading or writing this fd is never safe, except when done from read_from_fd() / write_to_fd() of a specialized class like TLSSocket.
  int get_fd() const { return m_fd; }

 protected:
  // Stream socket peer closed connection before reading all data that was sent, or shut down writing half of connection (ie a pipe(2)).
  //
  // If this is not an OutputDevice then this default will be used: the HUP is ignored. The idea is that in most cases this will
  // be an InputDevice and a HUP on a pure InputDevice is most likely a PipeReadEnd where the writing end of the pipe(2) was closed.
  // We cannot and should not close the read end too: there might still be more data to read. Note that getting here in that case
  // is extremely rare because normally we handle EPOLLIN before EPOLLHUP and should reach the EOF (read(2) returning 0) before
  // handling the HUP. However, if the receive buffer is full - then we stop reading (remove EPOLLIN from the epoll interest list)
  // while there is still more to read. In that case, if the writing half of the connection was closed, we get here and do nothing
  // thus, so that we get a chance to read the rest in the pipe line.
  virtual void hup(int& UNUSED_ARG(allow_deletion_count), int UNUSED_ARG(fd)) { }

  // There is some error condition on the file descriptor (not a HUP).
  // FIXME: when do we get here? Is closing always the right thing to do?
  virtual void err(int& UNUSED_ARG(allow_deletion_count), int UNUSED_ARG(fd)) { close(); }

  // Called by close(). These will be overridden by InputDevice and/or OutputDevice.
  // The default does nothing so that close() can simply call both and then get InputDevice::close_input_device(),
  // OutputDevice::close_output_device() or both, depending on this is a base class of InputDevice, OutputDevice
  // or both.
  virtual void close_input_device(int& UNUSED_ARG(allow_deletion_count)) { }
  virtual void close_output_device(int& UNUSED_ARG(allow_deletion_count)) { }

  // Events.
  // The filedescriptor of this device was just closed.
  // If INTERNAL_FDS_DONT_CLOSE is set then the fd wasn't really closed, but this method is still called.
  // When we get here the object is also marked as FDS_DEAD.
  virtual void closed(int& UNUSED_ARG(allow_deletion_count)) { }

 public:
  RefCountReleaser close_input_device()
  {
    int allow_deletion_count = 0;
    close_input_device(allow_deletion_count);
    return {this, allow_deletion_count};
  }

  RefCountReleaser close_output_device()
  {
    int allow_deletion_count = 0;
    close_output_device(allow_deletion_count);
    return {this, allow_deletion_count};
  }

  RefCountReleaser close()
  {
    int allow_deletion_count = 0;
    close_input_device(allow_deletion_count);
    close_output_device(allow_deletion_count);
    return {this, allow_deletion_count};
  }

  // Overload for internal (non-public) call.
  void close(int& allow_deletion_count)
  {
    close_input_device(allow_deletion_count);
    close_output_device(allow_deletion_count);
  }

#if CW_DEBUG
  void print_tracker_info_on(std::ostream& os) const
  {
    os << this << ": " << get_fd() << ", " << get_flags();
  }
#endif
};

std::ostream& operator<<(std::ostream& os, FileDescriptor::State const& state);

// Convenience function to create devices.
template<typename DeviceType, typename... ARGS, typename = typename std::enable_if<std::is_base_of<FileDescriptor, DeviceType>::value>::type>
boost::intrusive_ptr<DeviceType> create(ARGS&&... args)
{
#ifdef CWDEBUG
#if CWDEBUG_LOCATION
  LibcwDoutScopeBegin(LIBCWD_DEBUGCHANNELS, ::libcwd::libcw_do, dc::evio)
  LibcwDoutStream << "Entering evio::create<" << libcwd::type_info_of<DeviceType>().demangled_name();
  (LibcwDoutStream << ... << (std::string(", ") + libcwd::type_info_of<ARGS>().demangled_name())) << ">(" << join(", ", args...) << ')';
  LibcwDoutScopeEnd;
  ::NAMESPACE_DEBUG::Indent indentation(2);
#else
  DoutEntering(dc::evio, "evio::create<>(" << join(", ", args...) << ')')
#endif
#endif
  DeviceType* device = new DeviceType(std::forward<ARGS>(args)...);
  AllocTag2(device, "Created with evio::create");
  Dout(dc::evio, "Returning device pointer " << (void*)device << " [" << static_cast<FileDescriptor*>(device) << "].");
  return device;
}

} // namespace evio

#endif // EVIO_FILEDESCRIPTOR_H
