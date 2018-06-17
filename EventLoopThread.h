#pragma once

#include "evio.h"
#include "FileDescriptor.h"
#include "statefultask/AIThreadPool.h"
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>

class EventLoopThread
{
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
  EventLoopThread(AIQueueHandle handler);
  ~EventLoopThread();

  void start(ev_timer& timeout_watcher);
  void start(ev_io& io_watcher);

  void invoke_pending();
};
