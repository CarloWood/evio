// evio -- Event Driven I/O support.
//
//! @file
//! @brief Declaration of class EventLoopThread.
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

#include "InputDevice.h"
#include "OutputDevice.h"
#include "StreamBuf-threads.h"
#include "threadpool/AIThreadPool.h"
#include "utils/Singleton.h"
#include "utils/FuzzyBool.h"
#include "utils/AISignals.h"
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <functional>

namespace utils {

class FuzzyCondition : public FuzzyBool
{
 private:
  std::function<FuzzyBool()> m_condition_check;

 public:
  template<typename LAMBDA>
  FuzzyCondition(LAMBDA condition_check) : FuzzyBool{condition_check()}, m_condition_check(std::move(condition_check)) { }

  FuzzyBool operator()() const { return m_condition_check(); }

  friend std::ostream& operator<<(std::ostream& os, FuzzyCondition const& fuzzy_condition)
  {
    return os << "{FuzzyCondition: before: " << static_cast<FuzzyBool const&>(fuzzy_condition) << ", after: " << fuzzy_condition() << "}";
  }
};

} // namespace utils

namespace evio {

class EventLoop;

// Usage:
//
//   {
//     EventLoop event_loop(handler);
//     ...
//     event_loop.join();       // This blocks in the destructor of event_loop until the event loop did exit.
//                              // Therefore, do not create other objects in this scope that are needed for
//                              // this to work!
//   }
class EventLoopThread : public Singleton<EventLoopThread>
{
  // This is a singleton.
  // However, you must call EventLoopThread::instance().init(handler) to initialize it before use.
  // See above for the normal usage (aka, don't use EventLoopThread directly).
  friend_Instance;
  EventLoopThread() : m_epoll_fd(-1), m_epoll_signum(utils::Signals::reserve_and_next_rt_signum()), m_active(0), m_terminate(not_yet), m_running(false) { }
  ~EventLoopThread();
  EventLoopThread(EventLoopThread const&) = delete;

 private:
  std::thread m_event_thread;
  AIQueueHandle m_handler;
  int m_epoll_fd;
  static constexpr int maxevents = 32;
  static struct epoll_event s_events[maxevents];
  int const m_epoll_signum;
  std::atomic_int m_active;

#if 0
  std::mutex m_loop_mutex;
  std::condition_variable m_invoke_handled_cv;
  bool m_invoke_handled;
  bool m_inside_invoke_pending;
#endif
  enum terminate_type { not_yet, cleanly, forced } m_terminate;

  std::atomic_bool m_running;
  std::atomic_bool m_stop_running;

#if 0
  static void acquire_cb();
  static void release_cb();
  static void invoke_pending_cb();
#endif

  void main();
//  void handle_invoke_pending();
  friend class EventLoop;
  void init(AIQueueHandle handler);     // Called from the constructor of EventLoop.
  void terminate(bool normal_exit);     // Called from the destructor of EventLoop; exit as soon as all watchers added by start() have finished.

  static void s_wakeup_handler(int);
  void wake_up();

 public:
  enum result_t
  {
    condition_failed,   // The condition was false, nothing was done.
    success,            // start_if: successfully started (the ACTIVE flag was set (and if the device supports epoll, now watching active_flag).
                        // stop_if: successfully stopped (the ACTIVE flag was cleared (and if the device supports epoll, no longer watching the active_flag).
    success_added       // Also means success, but start_if also set the ADDED flag (and added the fd to epoll if it supports epoll).
  };

 private:
  void handle_regular_file(FileDescriptorFlags::mask_t active_flag, FileDescriptor* device);
  bool start(FileDescriptor::state_t::wat const& state_w, FileDescriptorFlags::mask_t active_flag, FileDescriptor* device);
  void stop(FileDescriptor::state_t::wat const& state_w, FileDescriptorFlags::mask_t active_flag, FileDescriptor* device);
  bool remove(FileDescriptor::state_t::wat const& state_w, FileDescriptorFlags::mask_t active_flag, FileDescriptor* device);
  result_t start_if(FileDescriptor::state_t::wat const& state_w, utils::FuzzyCondition const& condition, FileDescriptorFlags::mask_t active_flag, FileDescriptor* device);
  result_t stop_if(FileDescriptor::state_t::wat const& state_w, utils::FuzzyCondition const& condition, FileDescriptorFlags::mask_t active_flag, FileDescriptor* device);

 public:
  [[gnu::always_inline]] bool start(FileDescriptor::state_t::wat const& state_w, InputDevice* input_device) { return start(state_w, FileDescriptorFlags::FDS_R_ACTIVE, input_device); }
  [[gnu::always_inline]] bool start(FileDescriptor::state_t::wat const& state_w, OutputDevice* output_device) { return start(state_w, FileDescriptorFlags::FDS_W_ACTIVE, output_device); }
  [[gnu::always_inline]] void stop(FileDescriptor::state_t::wat const& state_w, InputDevice* input_device) { stop(state_w, FileDescriptorFlags::FDS_R_ACTIVE, input_device); }
  [[gnu::always_inline]] void stop(FileDescriptor::state_t::wat const& state_w, OutputDevice* output_device) { stop(state_w, FileDescriptorFlags::FDS_W_ACTIVE, output_device); }
  [[gnu::always_inline]] bool remove(FileDescriptor::state_t::wat const& state_w, InputDevice* input_device) { return remove(state_w, FileDescriptorFlags::FDS_R_ACTIVE, input_device); }
  [[gnu::always_inline]] bool remove(FileDescriptor::state_t::wat const& state_w, OutputDevice* output_device) { return remove(state_w, FileDescriptorFlags::FDS_W_ACTIVE, output_device); }
  [[gnu::always_inline]] result_t start_if(FileDescriptor::state_t::wat const& state_w, utils::FuzzyCondition const& condition, InputDevice* input_device) { return start_if(state_w, condition, FileDescriptorFlags::FDS_R_ACTIVE, input_device); }
  [[gnu::always_inline]] result_t start_if(FileDescriptor::state_t::wat const& state_w, utils::FuzzyCondition const& condition, OutputDevice* output_device) { return start_if(state_w, condition, FileDescriptorFlags::FDS_W_ACTIVE, output_device); }
  [[gnu::always_inline]] result_t stop_if(FileDescriptor::state_t::wat const& state_w, utils::FuzzyCondition const& condition, InputDevice* input_device) { return stop_if(state_w, condition, FileDescriptorFlags::FDS_R_ACTIVE, input_device); }
  [[gnu::always_inline]] result_t stop_if(FileDescriptor::state_t::wat const& state_w, utils::FuzzyCondition const& condition, OutputDevice* output_device) { return stop_if(state_w, condition, FileDescriptorFlags::FDS_W_ACTIVE, output_device); }

//  void invoke_pending();
  void stop_running();

  // Call this from the call back of a timer when that expires
  // AFTER you already called terminate(), in order to wake up
  // the event loop thread again. If terminate() wasn't called
  // then it has no effect. You could add it to every timer
  // call back if you want, but it has to take the lock on
  // m_loop_mutex shortly so that might be a waste.
  void bump_terminate();

#if 0
  // Obtain id of the Event Loop Thread. Mainly for debugging purposes.
  std::thread::id id() const { return m_event_thread.get_id(); }

  class TemporaryRelease
  {
   public:
    TemporaryRelease() { EventLoopThread::release_cb(); }
    ~TemporaryRelease() { EventLoopThread::acquire_cb(); }
  };

  static TemporaryRelease temporary_release()
  {
    return TemporaryRelease();
  }
#endif
};

class EventLoop
{
 private:
  bool m_normal_exit;

 public:
  EventLoop(AIQueueHandle handler);
  ~EventLoop();

 // Call this immediately before the EventLoop leaves scope in order
 // to make the EventLoopThread *finish* what it was doing before terminating.
 // Leaving the scope by exception (without calling join()) then will force the EventLoop to terminate abruptly.
 void join() { m_normal_exit = true; }
};

} // namespace evio

#if 0
#ifdef CWDEBUG
inline bool in_event_loop_thread()
{
  return evio::EventLoopThread::instance().id() == std::this_thread::get_id();
}
#endif
#endif
