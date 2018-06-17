#include "sys.h"
#include "FileDescriptor.h"
#include "EventLoopThread.h"
#include "libcwd/buf2str.h"

namespace evio {

void FileDescriptor::evio_cb(EV_P_ ev_io* w, int revents)
{
  Dout(dc::notice, "Calling FileDescriptor::evio_cb(w, " << revents << ")");
  if ((revents & READ))
  {
    char buf[256];
    ssize_t len;
    do
    {
      len = read(w->fd, buf, 256);
      Dout(dc::notice, "Read: \"" << libcwd::buf2str(buf, len) << "\".");
    }
    while (len == 256);
    if (len == 5 && strncmp(buf, "quit\n", 5) == 0)
      ev_break(EV_A_ EVBREAK_ALL);
  }
  if ((revents & WRITE))
  {
    write(w->fd, "Hello world!\n", 13);
  }
}

void FileDescriptor::init(int fd, events_type events)
{
  // Don't call init() while the FileDescriptor is already active.
  ASSERT(!is_active());
  // events must be READ, WRITE or READ|WRITE.
  ASSERT(events != NONE && events == (events & (READ|WRITE)));
  ev_io_init(&m_io, FileDescriptor::s_evio_cb, fd, events);
  m_io.data = this;
}

void FileDescriptor::start(EventLoopThread& evio_loop)
{
  // Call FileDescriptor::init before calling FileDescriptor::start.
  ASSERT(m_io.events != EV_UNDEF);
  // Don't call start twice on a row.
  ASSERT(!is_active());
  evio_loop.start(m_io);
}

} // namespace evio
