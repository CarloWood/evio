/**
 * evio -- A cwm4 git submodule for adding support for buffered, iostream oriented, epoll based I/O.
 *
 * @file
 * @brief Definition of namespace evio; class FileDescriptor.
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
#include "debug.h"
#include "FileDescriptor.h"
#include "EventLoopThread.h"
#include <unistd.h>     // Needed for fcntl.
#include <fcntl.h>

char const* epoll_op_str(int op)
{
  switch (op)
  {
    AI_CASE_RETURN(EPOLL_CTL_ADD);
    AI_CASE_RETURN(EPOLL_CTL_MOD);
    AI_CASE_RETURN(EPOLL_CTL_DEL);
  }
  return "Unknown epoll op";
}

char const* epoll_event_str(uint32_t event)
{
  switch (event)
  {
    AI_CASE_RETURN(EPOLLIN);
    AI_CASE_RETURN(EPOLLOUT);
    AI_CASE_RETURN(EPOLLRDHUP);
    AI_CASE_RETURN(EPOLLPRI);
    AI_CASE_RETURN(EPOLLERR);
    AI_CASE_RETURN(EPOLLHUP);
    AI_CASE_RETURN(EPOLLET);
    AI_CASE_RETURN(EPOLLONESHOT);
    AI_CASE_RETURN(EPOLLWAKEUP);
    AI_CASE_RETURN(EPOLLEXCLUSIVE);
  }
  return "Unknown epoll event";
}

std::string epoll_events_str(uint32_t events)
{
  std::string result;
  char const* separator = "";
  for (uint32_t event = 1; event != 0; event <<= 1)
    if ((events & event))
    {
      result += separator;
      result += epoll_event_str(event);
      separator = "|";
    }
  return result;
}

std::ostream& operator<<(std::ostream& os, epoll_event const& event)
{
  return os << "{events:" << epoll_events_str(event.events) << ", data:" << static_cast<evio::FileDescriptor*>(event.data.ptr) << "}";
}

namespace evio {

void set_nonblocking(int fd)
{
  if (fd <= 2)
  {
    // You don't want to do this; it will only result in std::out / std::cerr to go 'bad' and not printing anything anymore.
    // See https://stackoverflow.com/questions/32508801/fprintf-stdcout-doesnt-print-part-of-the-string-to-stdout-stderr
    Dout(dc::warning, "Setting fd " << fd << " to non-blocking will cause all standard streams to become non-blocking "
        "which in turn will cause erratic write failures to the standard output streams causing them to go bad and stop "
        "displaying output.");
  }
  int res;
  if ((res = fcntl(fd, F_GETFL)) == -1)
    perror("fcntl(fd, F_GETFL)");
  else
  {
    if (!(res & O_NONBLOCK))
    {
      // On linux you can create stuff non-blocking from the start. So this should never be needed.
      Dout(dc::warning, "O_NONBLOCK is not set on fd " << fd);
      if (fcntl(fd, F_SETFL, res | O_NONBLOCK) == -1)
        perror("fcntl(fd, F_SETL, O_NONBLOCK)");
    }
#ifdef O_CLOEXEC
    if ((res = fcntl(fd, F_GETFD)) == -1)
      perror("fcntl(fd, F_GETFD)");
    else if (!(res & FD_CLOEXEC))
      Dout(dc::warning, "FD_CLOEXEC is not set on fd " << fd);
#endif
  }
  return;
}

bool is_valid(int fd)
{
#ifdef _WIN32
  return EV_FD_TO_WIN32_HANDLE (fd) != -1;
#elif defined(CW_CONFIG_NONBLOCK_SYSV)
#error "Not implemented."
#else
  return fcntl(fd, F_GETFL) != -1;
#endif
}

void FileDescriptor::init(int fd, bool make_fd_non_blocking)
{
  DoutEntering(dc::evio, "FileDescriptor::init(" << fd << ") [" << this << ']');
  // Close the device before opening it again.
  ASSERT(!is_valid(m_fd));
  // Only call init() with a valid, open filedescriptor.
  ASSERT(is_valid(fd));

  if (make_fd_non_blocking)
    set_nonblocking(fd);

  // Reset all flags except FDS_RW and FDS_REGULAR_FILE.
  state_t::wat state_w(m_state);
  state_w->m_flags.reset();
  m_fd = fd;
  init_input_device(state_w);
  init_output_device(state_w);
}

std::ostream& operator<<(std::ostream& os, FileDescriptorFlags const& flags)
{
  if (flags.is_output_device())
    os << (flags.is_input_device() ? "FDS_RW" : "FDS_W");
  else if (flags.is_input_device())
    os << "FDS_R";

  if (flags.is_w_close())
    os << "|FDS_W_CLOSE";

  if (flags.dont_close())
    os << "|INTERNAL_FDS_DONT_CLOSE";

  if (flags.is_r_inferior())
    os << "|FDS_R_INFERIOR";
  if (flags.is_w_inferior())
    os << "|FDS_W_INFERIOR";

  if (flags.is_regular_file())
    os << "|FDS_REGULAR_FILE";

  if (flags.is_w_flushing())
    os << "|FDS_W_FLUSHING";

  if (flags.is_r_disabled())
    os << "|FDS_R_DISABLED";
  if (flags.is_w_disabled())
    os << "|FDS_W_DISABLED";

  if (flags.is_r_open())
    os << "|FDS_R_OPEN";
  if (flags.is_w_open())
    os << "|FDS_W_OPEN";
  if (flags.is_same())
    os << "|FDS_SAME";

  if (flags.is_dead())
    os << "|FDS_DEAD";

  if (flags.is_r_added())
    os << "|FDS_R_ADDED";
  if (flags.is_w_added())
    os << "|FDS_W_ADDED";

  if (flags.is_active_input_device())
    os << "|FDS_R_ACTIVE";
  if (flags.is_active_output_device())
    os << "|FDS_W_ACTIVE";

  if (flags.is_r_busy())
    os << "|FDS_R_BUSY";
  if (flags.is_w_busy())
    os << "|FDS_W_BUSY";

#ifdef CWDEBUG
  if (flags.is_debug_channel())
    os << "|FDS_DEBUG";
#endif

  return os;
}

std::ostream& operator<<(std::ostream& os, FileDescriptor::State const& state)
{
  return os << "{m_flags:" << state.m_flags << ", m_epoll_event:" << state.m_epoll_event << "}";
}

void intrusive_ptr_release(FileDescriptor const* ptr)
{
  int prev_count = ptr->AIRefCount::allow_deletion(true);
  Dout(dc::io, "Decremented ref count of device " << ptr << " to " << (prev_count - 1));
  if (prev_count == 1)
  {
    std::atomic_thread_fence(std::memory_order_acquire);
    // We must use delayed deletion, because the EventLoopThread might already have gotten a pointer to the object from epoll_pwait().
    // I addressed the problem here: https://lkml.org/lkml/2019/7/11/747 ; but never got an answer, so resorting to this user-space "solution".
    EventLoopThread::instance().add_needs_deletion(ptr);
  }
}

void FileDescriptor::allow_deletion(int count) const
{
  // Prevent a double deletion.
  if (AI_UNLIKELY(count == 0))
    return;
  int prev_count = AIRefCount::allow_deletion(true, count);
  Dout(dc::io, "Decremented ref count of device " << this << " to " << (prev_count - count));
  // Paranoia check. Fix library if this ever fires again.
  ASSERT(count <= prev_count);
  if (prev_count == count)
    EventLoopThread::instance().add_needs_deletion(this);
}

} // namespace evio
