#include "sys.h"
#include "FileDescriptor.h"
#include "EventLoopThread.h"
#include "libcwd/buf2str.h"

namespace evio {

void InputDevice::evio_cb(EV_P_ ev_io* w, int DEBUG_ONLY(revents))
{
  Dout(dc::notice, "Calling InputDevice::evio_cb(w, " << revents << ")");
  ASSERT(revents == EV_READ);
  char buf[256];
  ssize_t len;
  do
  {
    len = read(w->fd, buf, 256);
    Dout(dc::notice, "Read: \"" << libcwd::buf2str(buf, len) << "\".");
  }
  while (len == 256);
  if (strncmp(buf + len - 17, "#5</body></html>\n", 17) == 0)
  {
    stop_input_device();
    ev_break(EV_A_ EVBREAK_ALL);
  }
}

void OutputDevice::evio_cb(EV_P_ ev_io* w, int DEBUG_ONLY(revents))
{
  Dout(dc::notice, "Calling OutputDevice::evio_cb(w, " << revents << ")");
  ASSERT(revents == EV_WRITE);
  static int request = 0;
  if (request < 6)
  {
    std::stringstream ss;
    ss << "GET / HTTP/1.1\r\nHost: localhost:9001\r\nAccept: */*\r\nX-Request: " << request++ << "\r\nX-Sleep: 100\r\n\r\n";
    write(w->fd, ss.str().data(), ss.str().length());
    Dout(dc::notice, "Wrote \"" << libcwd::buf2str(ss.str().data(), ss.str().length()) << "\".");
  }
  else
  {
    stop_output_device();
  }
}

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
