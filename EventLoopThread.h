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
#include "Device.h"
#include "statefultask/AIThreadPool.h"
#include "utils/Singleton.h"
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>

class EventLoopThread : public Singleton<EventLoopThread>
{
  // This is a singleton.
  // However, you must call EventLoopThread::instance().init(handler) to initialize it before use.
  friend_Instance;
  EventLoopThread() : m_inside_invoke_pending(false) { }
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

  ev_async m_async_w;
  std::atomic_bool m_running;

  static void acquire_cb(EV_P);
  static void release_cb(EV_P);
  static void invoke_pending_cb(EV_P);
  static void async_cb(EV_P_ ev_async* w, int revents);
  static void main(EV_P);

  void run();
  void handle_invoke_pending();

 public:
  void init(AIQueueHandle handler);
  void join();

  static void start(ev_timer& timeout_watcher);
  static void start(ev_io& io_watcher);

  void invoke_pending();
};
