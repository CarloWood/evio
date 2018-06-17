#pragma once

#include "evio.h"
#include "utils/sbll.h"
#include "utils/AIRefCount.h"

class EventLoopThread;

namespace evio {

class FileDescriptor : public AIRefCount
{
 private:
  friend EventLoopThread; // Needs access to m_io.
  ev_io m_io;

 private:
   void evio_cb(EV_P_ ev_io* w, int revents);
   static void s_evio_cb(EV_P_ ev_io* w, int revents) { static_cast<FileDescriptor*>(w->data)->evio_cb(w, revents); }

 public:
  FileDescriptor()
  {
    // Give m_io known values; cause is_active() to return false.
    ev_io_init(&m_io, FileDescriptor::s_evio_cb, -1, EV_UNDEF);
  }

  // (Re)Initialize the FileDescriptor.
  void init(int fd, events_type events);

  // Add filedescriptor to libev for monitoring.
  void start(EventLoopThread& evio_loop);

  bool is_active() const { return ev_is_active(&m_io); }
};

} // namespace evio
