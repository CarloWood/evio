// evio -- Event Driven I/O support.
//
//! @file
//! @brief Definition of namespace evio; class InputDevice and OutputDevice.
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

#include "sys.h"
#include "FileDescriptor.h"
#include "EventLoopThread.h"
#include "libcwd/buf2str.h"

namespace evio {

void InputDevice::init_input_device(int fd)
{
  // Don't call init() while the InputDevice is already active.
  ASSERT(!is_active());
  ev_io_init(&m_input_watcher, InputDevice::s_evio_cb, fd, EV_READ);
  m_input_watcher.data = this;
}

void OutputDevice::init_output_device(int fd)
{
  // Don't call init() while the OutputDevice is already active.
  ASSERT(!is_active());
  ev_io_init(&m_output_watcher, OutputDevice::s_evio_cb, fd, EV_WRITE);
  m_output_watcher.data = this;
}

void InputDevice::start_input_device(EventLoopThread& evio_loop)
{
  // Call InputDevice::init before calling InputDevice::start.
  ASSERT(m_input_watcher.events != EV_UNDEF);
  // Don't call start twice on a row.
  ASSERT(!is_active());
  evio_loop.start(m_input_watcher);
  intrusive_ptr_add_ref(this);
}

void OutputDevice::start_output_device(EventLoopThread& evio_loop)
{
  // Call OutputDevice::init before calling OutputDevice::start.
  ASSERT(m_output_watcher.events != EV_UNDEF);
  // Don't call start twice on a row.
  ASSERT(!is_active());
  evio_loop.start(m_output_watcher);
  intrusive_ptr_add_ref(this);
}

void InputDevice::stop_input_device()
{
  if (is_active())
  {
    ev_io_stop(EV_A_ &m_input_watcher);
    intrusive_ptr_release(this);
  }
}

void OutputDevice::stop_output_device()
{
  if (is_active())
  {
    ev_io_stop(EV_A_ &m_output_watcher);
    intrusive_ptr_release(this);
  }
}

} // namespace evio
