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

#include "evio.h"
#include "StreamBuf-threads.h"
#include "threadpool/AIThreadPool.h"
#include "utils/Singleton.h"
#include "utils/FuzzyBool.h"
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

class FileDescriptor;
class EventLoop;

class EventLoopThread : public Singleton<EventLoopThread>
{
  // This is a singleton.
  // However, you must call EventLoopThread::instance().init(handler) to initialize it before use.
  friend_Instance;
  EventLoopThread() : m_inside_invoke_pending(false), m_terminate(not_yet) { }
  ~EventLoopThread();
  EventLoopThread(EventLoopThread const&) = delete;

 private:
  std::thread m_event_thread;
  AIQueueHandle m_handler;

#if EV_MULTIPLICITY
  struct ev_loop* loop;
#endif
  std::mutex m_loop_mutex;
  std::condition_variable m_invoke_handled_cv;
  bool m_invoke_handled;
  bool m_inside_invoke_pending;
  enum terminate_type { not_yet, cleanly, forced } m_terminate;

  ev_async m_async_w;
  std::atomic_bool m_running;

  static void acquire_cb(EV_P) EV_THROW;
  static void release_cb(EV_P) EV_THROW;
  static void invoke_pending_cb(EV_P);
  static void async_cb(EV_P_ ev_async* w, int revents);
  static void main(EV_P);

  void run();
  void handle_invoke_pending();
  friend class EventLoop;
  void init(AIQueueHandle handler);     // Called from the constructor of EventLoop.
  void terminate(bool normal_exit);     // Called from the destructor of EventLoop; exit as soon as all watchers added by start() have finished.

 public:

  template<class ThreadType>
  utils::FuzzyBool is_active_input_device(ev_io const& io_watcher, ThreadType)
  {
    constexpr bool get_thread = std::is_base_of<GetThread, ThreadType>::value;
    constexpr bool put_thread = std::is_base_of<PutThread, ThreadType>::value;
    static_assert(get_thread || put_thread || std::is_same<AnyThread, ThreadType>::value,
                  "May only be called with ThreadType is SingleThread, AnyThread, GetThread or PutThread.");

    std::lock_guard<std::mutex> lock(m_loop_mutex);

    // Basically we need the following table to hold:
    //  Currently active  SingleThread    AnyThread       GetThread       PutThread
    //       yes          WasTrue         WasTrue         WasTrue         WasTrue
    //        no          False           WasFalse        False           WasFalse
    //
    return ev_is_active(&io_watcher) ? fuzzy::WasTrue : (get_thread ? fuzzy::False : fuzzy::WasFalse);
  }

  template<class ThreadType>
  utils::FuzzyBool is_active_output_device(ev_io const& io_watcher, ThreadType)
  {
    constexpr bool get_thread = std::is_base_of<GetThread, ThreadType>::value;
    constexpr bool put_thread = std::is_base_of<PutThread, ThreadType>::value;
    static_assert(get_thread || put_thread || std::is_same<AnyThread, ThreadType>::value,
                  "May only be called with ThreadType is SingleThread, AnyThread, GetThread or PutThread.");

    std::lock_guard<std::mutex> lock(m_loop_mutex);

    // Basically we need the following table to hold:
    //  Currently active  SingleThread    AnyThread       GetThread       PutThread
    //       yes          WasTrue         WasTrue         WasTrue         WasTrue
    //        no          False           WasFalse        WasFalse        False
    //
    return ev_is_active(&io_watcher) ? fuzzy::WasTrue : (put_thread ? fuzzy::False : fuzzy::WasFalse);
  }

  void start(ev_timer& timeout_watcher);
  bool start(ev_io* io_watcher, evio::FileDescriptor* device);
  bool stop(ev_io* io_watcher);
  bool start_if(utils::FuzzyCondition const& condition, ev_io* io_watcher, evio::FileDescriptor* device);
  bool stop_if(utils::FuzzyCondition const& condition, ev_io* io_watcher);

  void invoke_pending();

  // Call this from the call back of a timer when that expires
  // AFTER you already called terminate(), in order to wake up
  // the event loop thread again. If terminate() wasn't called
  // then it has no effect. You could add it to every timer
  // call back if you want, but it has to take the lock on
  // m_loop_mutex shortly so that might be a waste.
  void bump_terminate();

  // Obtain id of the Event Loop Thread. Mainly for debugging purposes.
  std::thread::id id() const { return m_event_thread.get_id(); }

  class TemporaryRelease
  {
#if EV_MULTIPLICITY
    struct ev_loop* m_loop;
   public:
    TemporaryRelease(EV_P) : m_loop(loop) { EventLoopThread::release_cb(loop); }
    ~TemporaryRelease() { EventLoopThread::acquire_cb(m_loop); }
#else
   public:
    TemporaryRelease() { EventLoopThread::release_cb(); }
    ~TemporaryRelease() { EventLoopThread::acquire_cb(); }
#endif
  };

  static TemporaryRelease temporary_release(EV_P)
  {
    return TemporaryRelease(EV_A);
  }
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

#ifdef CWDEBUG
inline bool in_event_loop_thread()
{
  return evio::EventLoopThread::instance().id() == std::this_thread::get_id();
}
#endif
