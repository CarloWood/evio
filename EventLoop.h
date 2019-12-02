/**
 * evio -- A cwm4 git submodule for adding support for buffered, iostream oriented, epoll based I/O.
 *
 * @file
 * @brief Declaration of class EventLoop.
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

#pragma once

// This header file doesn't require this, but the TU that uses this header will also need EventLoopThread.
#include "EventLoopThread.h"    // This drags in AIQueueHandle too though.
// Same for this header.
#include "threadpool/AIThreadPool.h"

namespace evio {

// Usage:
//
//   AIThreadPool thread_pool;
//   ...
//   AIQueueHandle low_priority_handler = thread_pool.new_queue(16);
//
//   try
//   {
//     evio::EventLoop event_loop(low_priority_handler);
//
//     ...
//
//     // This blocks in the destructor of event_loop until the event loop did exit.
//     // Therefore, do not create other objects in this scope that are needed for this to work!
//     event_loop.join();
//   }

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
