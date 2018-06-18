#pragma once

#include "evio.h"
#include "utils/sbll.h"
#include "utils/AIRefCount.h"

class EventLoopThread;

namespace evio {

// Virtual base class for IO Devices.
//
// This class takes care of the life-time of an Input-, Output- or IO-Device.
class IOBase : public AIRefCount
{
 protected:
  virtual void init_input_device(int) { }
  virtual void init_output_device(int) { }
  virtual void start_input_device(EventLoopThread&) { }
  virtual void start_output_device(EventLoopThread&) { }
  virtual void stop_input_device() { }
  virtual void stop_output_device() { }

#ifdef CWDEBUG
  ~IOBase() { Dout(dc::notice, "Destructing IOBase [" << (void*)this << "]"); }
#endif

 public:
  // (Re)Initialize the FileDescriptor.
  void init(int fd)
  {
    init_input_device(fd);
    init_output_device(fd);
  }

  void start(EventLoopThread& evio_loop)
  {
    start_input_device(evio_loop);
    start_output_device(evio_loop);
  }

  void stop()
  {
    stop_input_device();
    stop_output_device();
  }
};

class InputDevice : public virtual IOBase
{
 private:
  friend EventLoopThread; // Needs access to m_input_watcher.
  ev_io m_input_watcher;

 private:
  void evio_cb(EV_P_ ev_io* w, int revents);
  static void s_evio_cb(EV_P_ ev_io* w, int revents) { static_cast<InputDevice*>(w->data)->evio_cb(w, revents); }

  void init_input_device(int fd) override;
  void start_input_device(EventLoopThread& evio_loop) override;
  void stop_input_device() override;

 public:
  InputDevice()
  {
    // Give m_input_watcher known values; cause is_active() to return false.
    ev_io_init(&m_input_watcher, InputDevice::s_evio_cb, -1, EV_UNDEF);
  }

  bool is_active() const { return ev_is_active(&m_input_watcher); }

 protected:
  int fd() const { return m_input_watcher.fd; }
  virtual void read_from_fd();
};

class OutputDevice : public virtual IOBase
{
 private:
  friend EventLoopThread; // Needs access to m_output_watcher.
  ev_io m_output_watcher;

 private:
  void evio_cb(EV_P_ ev_io* w, int revents);
  static void s_evio_cb(EV_P_ ev_io* w, int revents) { static_cast<OutputDevice*>(w->data)->evio_cb(w, revents); }

  void init_output_device(int fd) override;
  void start_output_device(EventLoopThread& evio_loop) override;
  void stop_output_device() override;

 public:
  OutputDevice()
  {
    // Give m_output_watcher known values; cause is_active() to return false.
    ev_io_init(&m_output_watcher, OutputDevice::s_evio_cb, -1, EV_UNDEF);
  }

  bool is_active() const { return ev_is_active(&m_output_watcher); }

 protected:
  int fd() const { return m_output_watcher.fd; }
  virtual void write_to_fd();
};

} // namespace evio
