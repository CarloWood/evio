/**
 * evio -- A cwm4 git submodule for adding support for buffered, iostream oriented, epoll based I/O.
 *
 * @file
 * @brief Definition of class EventLoop.
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

#include "sys.h"
#include "EventLoop.h"
#include "debug.h"
#ifdef CWDEBUG
#include <libcwd/buf2str.h>
#endif

namespace evio {

// EventLoop constructor.
EventLoop::EventLoop(AIQueueHandle handler, std::string color_on_str, std::string color_off_str) : m_normal_exit(false)
{
  DoutEntering(dc::evio, "EventLoop::EventLoop(" << handler << ", \"" <<
      buf2str(color_on_str.data(), color_on_str.size()) << "\", \"" << buf2str(color_off_str.data(), color_off_str.size()) << "\")");
  EventLoopThread::instance().init(handler, color_on_str, color_off_str);
}

EventLoop::~EventLoop()
{
  DoutEntering(dc::evio, "EventLoop::~EventLoop()");
  if (!m_normal_exit)
    // Normally you want to call event_loop.join() at the end of the scope of an EventLoop event_loop(handler);
    Dout(dc::warning, "Unclean exit from EventLoop!");
  EventLoopThread::instance().terminate(m_normal_exit);
}

} // namespace evio
