#include "sys.h"
#include "evio/EventLoopThread.h"
#include "statefultask/AIThreadPool.h"
#include "debug.h"
#include <chrono>

//static
void EventLoopThread::acquire_cb(EV_P)
{
  EventLoopThread* event_loop_thread = static_cast<EventLoopThread*>(ev_userdata(EV_A));
  Dout(dc::notice|flush_cf, (event_loop_thread->m_inside_invoke_pending ? "thread pool" : "ev_run thread") << " returned from epoll_wait()");
  event_loop_thread->m_loop_mutex.lock();
}

//static
void EventLoopThread::release_cb(EV_P)
{
  EventLoopThread* event_loop_thread = static_cast<EventLoopThread*>(ev_userdata(EV_A));
  event_loop_thread->m_loop_mutex.unlock();
  Dout(dc::notice|flush_cf, (event_loop_thread->m_inside_invoke_pending ? "thread pool" : "ev_run thread") << " calls epoll_wait()...");
}

//static
void EventLoopThread::invoke_pending_cb(EV_P)
{
  static_cast<EventLoopThread*>(ev_userdata(EV_A))->handle_invoke_pending();
}

//static
void EventLoopThread::main(EV_P)
{
  Debug(NAMESPACE_DEBUG::init_thread());
  Dout(dc::notice, "Event loop thread started.");
  static_cast<EventLoopThread*>(ev_userdata(EV_A))->run();
}

//static
void EventLoopThread::async_cb(
#if EV_MULTIPLICITY
    struct ev_loop* UNUSED_ARG(loop),
#endif
    ev_async* UNUSED_ARG(w), int UNUSED_ARG(revents))
{
  // Just used for the side effects.
  Dout(dc::notice, "Calling async_cb()");
}

void EventLoopThread::run()
{
  // Lock m_loop_mutex before calling ev_run.
  std::lock_guard<std::mutex> lock(m_loop_mutex);
  m_running = true;
  Dout(dc::notice, "Calling ev_run(0)");
  ev_run(EV_A_ 0);
  Dout(dc::notice, "Returned from ev_run(0)");
  m_running = false;
}

void EventLoopThread::invoke_pending()
{
  DoutEntering(dc::notice|flush_cf, "EventLoopThread::invoke_pending()");
  std::unique_lock<std::mutex> lock(m_loop_mutex);
  ASSERT(ev_pending_count(EV_A));
  ev_invoke_pending(EV_A);

  // Instead of returning control to the ev_run thread immediately, do a
  // quick poll here if there already more activity in the meantime.
  if (!m_inside_invoke_pending && !ev_requested_break(EV_A))
  {
    // No recursive calls.
    m_inside_invoke_pending = true;
    // Poll for additional events that might have occurred.
    ev_set_invoke_pending_cb(EV_A_ ev_invoke_pending);                  // Call ev_invoke_pending directly.
    Dout(dc::notice, "Entering ev_run(EVRUN_NOWAIT).");
    ev_run(EVRUN_NOWAIT);
    Dout(dc::notice, "Leaving ev_run(EVRUN_NOWAIT).");
    ev_set_invoke_pending_cb(EV_A_ EventLoopThread::invoke_pending_cb); // Restore normal operation.
    m_inside_invoke_pending = false;
  }

  // Notify ev_run thread.
  Dout(dc::notice, "Setting m_invoke_handled to true and notifying ev_run thread.");
  m_invoke_handled = true;
  m_invoke_handled_cv.notify_one();
}

void EventLoopThread::handle_invoke_pending()
{
  // Seriously, why does this even happen? The reason is apparently that libev
  // calls EV_INVOKE_PENDING at the beginning of ev_run, at which point it
  // obviously has nothing pending.
  if (!ev_pending_count(EV_A))
    return;

  DoutEntering(dc::notice|flush_cf, "EventLoopThread::handle_invoke_pending()");
  // The lock is already locked when we get here.
  std::unique_lock<std::mutex> lock(m_loop_mutex, std::adopt_lock);
  while (ev_pending_count(EV_A))
  {
    {
      AIThreadPool& thread_pool(AIThreadPool::instance());
      auto const max_duration = std::chrono::milliseconds(64);
      auto duration = std::chrono::milliseconds(1);
      auto queues_access = thread_pool.queues_read_access();
      auto& queue = thread_pool.get_queue(queues_access, m_handler);
      bool queue_was_full = false;
      bool queue_full;
      do
      {
        {
          auto queue_access = queue.producer_access();
          if (!(queue_full = queue_access.length() == queue.capacity()))
          {
            Dout(dc::notice, "Queuing call to invoke_pending() in thread pool queue " << m_handler);
            queue_access.move_in([this](){ invoke_pending(); return false; });
          }
        }
        if (queue_full)
        {
          if (!queue_was_full)
          {
            Dout(dc::warning, "Thread pool queue " << m_handler << " is full! Now no longer handling any filedescriptor I/O until this is resolved.");
            queue_was_full = true;
          }
          // Exponentially back off, sleeping 1, 2, 4, 8, 16, 32 and then 64 (repeated) ms.
          std::this_thread::sleep_for(duration);
          if (duration < max_duration)
            duration *= 2;
        }
      }
      while (queue_full);
      queue.notify_one();
      if (queue_was_full)
      {
        Dout(dc::warning, "Queue is no longer full; resuming I/O.");
      }
    }

    // Wait until invoke_pending() was called.
    m_invoke_handled = false;
    Dout(dc::notice, "Waiting for m_invoke_handled to become true.");
    m_invoke_handled_cv.wait(lock, [this](){ return m_invoke_handled; });
    Dout(dc::notice, "m_invoke_handled is now true.");
  }
  // Leave the mutex locked.
  lock.release();
  Dout(dc::notice|flush_cf, "Leaving EventLoopThread::handle_invoke_pending()");
}

EventLoopThread::EventLoopThread(AIQueueHandle handler) : m_handler(handler), m_inside_invoke_pending(false)
{
#if EV_MULTIPLICITY
  loop =
#endif
  ev_default_loop(EVBACKEND_EPOLL | EVFLAG_NOENV);

  // Associate `this` with the loop.
  ev_set_userdata(EV_A_ this);
  ev_set_loop_release_cb(EV_A_ EventLoopThread::release_cb, EventLoopThread::acquire_cb);
  ev_set_invoke_pending_cb(EV_A_ EventLoopThread::invoke_pending_cb);
  // Add an async watcher, this is used in add() to wake up the thread.
  ev_async_init(&m_async_w, EventLoopThread::async_cb);
  ev_async_start(EV_A_ &m_async_w);

  // Create the thread running ev_run.
  m_event_thread = std::thread([this](){ EventLoopThread::main(EV_A); });

  // Wait till we're actually running.
  while (!m_running)
    ;
}

EventLoopThread::~EventLoopThread()
{
  DoutEntering(dc::notice, "EventLoopThread::~EventLoopThread()");
  Dout(dc::notice, "Joining m_event_thread.");
  m_event_thread.join();
}

void EventLoopThread::start(ev_timer& timeout_watcher)
{
  std::lock_guard<std::mutex> lock(m_loop_mutex);
  ev_timer_start(EV_A_ &timeout_watcher);
  ev_async_send(EV_A_ &m_async_w);
}

void EventLoopThread::start(ev_io& io_watcher)
{
  std::lock_guard<std::mutex> lock(m_loop_mutex);
  ev_io_start(EV_A_ &io_watcher);
  ev_async_send(EV_A_ &m_async_w);
}
