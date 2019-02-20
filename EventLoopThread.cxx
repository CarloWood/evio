// evio -- Event Driven I/O support.
//
//! @file
//! @brief Definition of class EventLoopThread.
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
#include "evio/EventLoopThread.h"
#include "evio/FileDescriptor.h"
#include "threadpool/AIThreadPool.h"
#include "debug.h"
#include <chrono>

#if defined(CWDEBUG) && !defined(DOXYGEN)
NAMESPACE_DEBUG_CHANNELS_START
extern channel_ct evio;
NAMESPACE_DEBUG_CHANNELS_END
#endif

namespace evio {

//static
void EventLoopThread::acquire_cb(EV_P) EV_THROW
{
  EventLoopThread* event_loop_thread = static_cast<EventLoopThread*>(ev_userdata(EV_A));
  Dout(dc::evio|flush_cf, (event_loop_thread->m_inside_invoke_pending ? "thread pool" : "ev_run thread") << " returned from epoll_wait()");
  event_loop_thread->m_loop_mutex.lock();
}

//static
void EventLoopThread::release_cb(EV_P) EV_THROW
{
  EventLoopThread* event_loop_thread = static_cast<EventLoopThread*>(ev_userdata(EV_A));
  event_loop_thread->m_loop_mutex.unlock();
  Dout(dc::evio|flush_cf, (event_loop_thread->m_inside_invoke_pending ? "thread pool" : "ev_run thread") << " calls epoll_wait()...");
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
  Dout(dc::evio, "Event loop thread started.");
  static_cast<EventLoopThread*>(ev_userdata(EV_A))->run();
}

//static
void EventLoopThread::async_cb(
#if EV_MULTIPLICITY
    struct ev_loop* UNUSED_ARG(loop),
#endif
    ev_async* UNUSED_ARG(w), int UNUSED_ARG(revents))
{
  // Just used to wake up the main loop.
  Dout(dc::evio, "Calling async_cb()");
}

void EventLoopThread::run()
{
  // Lock m_loop_mutex before calling ev_run.
  std::lock_guard<std::mutex> lock(m_loop_mutex);
  m_running = true;
  Dout(dc::evio, "Calling ev_run(0)");
  ev_run(EV_A_ 0);
  Dout(dc::evio, "Returned from ev_run(0)");
  m_running = false;
}

void EventLoopThread::invoke_pending()
{
  DoutEntering(dc::evio|flush_cf, "EventLoopThread::invoke_pending()");
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
    Dout(dc::evio, "Entering ev_run(EVRUN_NOWAIT).");
    ev_run(EVRUN_NOWAIT);
    Dout(dc::evio, "Leaving ev_run(EVRUN_NOWAIT).");
    ev_set_invoke_pending_cb(EV_A_ EventLoopThread::invoke_pending_cb); // Restore normal operation.
    m_inside_invoke_pending = false;
  }

  // Notify ev_run thread.
  Dout(dc::evio, "Setting m_invoke_handled to true and notifying ev_run thread.");
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

  DoutEntering(dc::evio|flush_cf, "EventLoopThread::handle_invoke_pending()");
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
      DEBUG_ONLY(bool queue_was_full = false;)
      {
        bool queue_full;
        auto queue_access = queue.producer_access();
        do
        {
          if ((queue_full = queue_access.length() == queue.capacity()))
          {
            // Queue is full! Wait for a broadcast.
            Dout(dc::warning(!queue_was_full), "Thread pool queue " << m_handler << " is full! Now no longer handling any filedescriptor I/O until this is resolved.");
            Debug(queue_was_full = true);
            queue_access.wait();        // Wait until queue_access.notify_one() is called.
          }
          else
          {
            Dout(dc::warning(queue_was_full), "Queue is no longer full; resuming I/O.");
            Dout(dc::evio, "Queuing call to invoke_pending() in thread pool queue " << m_handler);
            queue_access.move_in([this](){ invoke_pending(); return false; });
          }
        }
        while (queue_full);
      }
      queue.notify_one();
    }

    // Wait until invoke_pending() was called.
    m_invoke_handled = false;
    Dout(dc::evio, "Waiting for m_invoke_handled to become true.");
    m_invoke_handled_cv.wait(lock, [this](){ return m_invoke_handled; });
    Dout(dc::evio, "m_invoke_handled is now true.");
  }
  // Leave the mutex locked.
  lock.release();
  Dout(dc::evio|flush_cf, "Leaving EventLoopThread::handle_invoke_pending()");
}

void EventLoopThread::init(AIQueueHandle handler)
{
  DoutEntering(dc::evio, "EventLoopThread::init(" << handler << ')');
  m_handler = handler;

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

void EventLoopThread::bump_terminate()
{
  std::lock_guard<std::mutex> lock(m_loop_mutex);
  if (m_terminate)
    ev_async_send(EV_A_ &m_async_w);    // Wake up the event loop (again) if we are terminating.
}

void EventLoopThread::terminate()
{
  DoutEntering(dc::evio, "EventLoopThread::terminate()");
  {
    std::lock_guard<std::mutex> lock(m_loop_mutex);
    m_terminate = true;
    ev_unref(EV_A);             // Cause ev_run to exit when only m_async_w is left.
    ev_async_send(EV_A_ &m_async_w);
  }
  if (m_event_thread.joinable())
  {
    Dout(dc::evio|continued_cf, "Joining m_event_thread... ");
    m_event_thread.join();
    Dout(dc::finish, "joined");
  }
}

EventLoopThread::~EventLoopThread()
{
  DoutEntering(dc::evio, "EventLoopThread::~EventLoopThread()");
  // Call EventLoopThread::instance().terminate() before leaving main().
  ASSERT(!m_event_thread.joinable());

  if (ev_userdata(EV_A) == this)        // Was init() called?
  {
    if (m_terminate)
      ev_ref(EV_A);
    ev_async_stop(EV_A_ &m_async_w);
  }
}

void EventLoopThread::start(ev_timer& timeout_watcher)
{
  std::lock_guard<std::mutex> lock(m_loop_mutex);
  ev_timer_start(EV_A_ &timeout_watcher);
  ev_async_send(EV_A_ &m_async_w);
}

bool EventLoopThread::start(ev_io* io_watcher, FileDescriptor* device)
{
  // Don't start a device that is disabled.
  if (device->is_disabled())
  {
    Dout(dc::warning, "Calling EventLoopThread::start(" << (void*)io_watcher << ") for a device that is disabled.");
    return false;
  }

  std::lock_guard<std::mutex> lock(m_loop_mutex);

  // Don't start a device that is already active.
  if (ev_is_active(io_watcher))
    return false;

  ev_io_start(EV_A_ io_watcher);
  ev_async_send(EV_A_ &m_async_w);
  return true;
}

bool EventLoopThread::start_if(utils::FuzzyCondition const& condition, ev_io* io_watcher, FileDescriptor* device)
{
  // Unlikely because you shouldn't call this function if this is the case, see below.
  if (AI_UNLIKELY(condition.is_false()))
  {
    Dout(dc::warning, "Calling EventLoopThread::start_if(" << condition << ", " << (void*)io_watcher << ")");
    return false;
  }

  // Don't start a device that is disabled.
  if (AI_UNLIKELY(device->is_disabled()))
  {
    Dout(dc::warning, "Calling EventLoopThread::start(" << condition << ", " << (void*)io_watcher << ") for a device that is disabled.");
    return false;
  }

  // This should never happen. First of all, for speed up reasons you should only call
  // this function when condition.is_momentary_true(), secondly if the condition would
  // be transitory_false it is nonsense to check the condition again here (we really
  // only want to call ev_io_start when the condition is true while m_loop_mutex is
  // locked) because if the condition changed from false to true due to another thread
  // then another thread either called this function or wrote to an empty buffer, both
  // of the cases means that it is a put thread; that should never happen since WE are
  // the put thread (only the put thread is expected to call this function).
  //
  // Another case where this assert might fail is when you call (for example)
  // start_output_device() from  a random thread without guaranteeing (by other means)
  // that the device is really stopped. For example, you should not call enable_output_device()
  // without first calling disable_output_device().
  ASSERT(!condition.is_transitory_false());

  std::lock_guard<std::mutex> lock(m_loop_mutex);

  // Don't start a device that is already active.
  if (ev_is_active(io_watcher))
    return false;

  // This is likely because otherwise we shouldn't be using a construction with
  // FuzzyBool / FuzzyCondition in the first place.
  if (AI_LIKELY(condition.is_transitory_true()))
  {
    // Re-test condition in critical area.
    if (!condition())
      return false;
  }
#ifdef CWDEBUG
  else
    Dout(dc::warning, "Calling EventLoopThread::start_if(" << condition << ", " << (void*)io_watcher << ")");
#endif

  ev_io_start(EV_A_ io_watcher);
  ev_async_send(EV_A_ &m_async_w);
  return true;
}

bool EventLoopThread::stop(ev_io* io_watcher)
{
  std::lock_guard<std::mutex> lock(m_loop_mutex);

  // Don't stop a device that is already non-active.
  if (!ev_is_active(io_watcher))
    return false;

  ev_io_stop(EV_A_ io_watcher);
  return true;
}

bool EventLoopThread::stop_if(utils::FuzzyCondition const& condition, ev_io* io_watcher)
{
  // Unlikely because you shouldn't call this function if this is the case, see below.
  if (AI_UNLIKELY(condition.is_false()))
  {
    Dout(dc::warning, "Calling EventLoopThread::stop_if(" << condition << ", " << (void*)io_watcher << ")");
    return false;
  }

  // See start_if.
  ASSERT(!condition.is_transitory_false());

  std::lock_guard<std::mutex> lock(m_loop_mutex);

  // Don't stop a device that is already non-active.
  if (!ev_is_active(io_watcher))
    return false;

  // This is likely because otherwise we shouldn't be using a construction with
  // FuzzyBool / FuzzyCondition in the first place.
  if (AI_LIKELY(condition.is_transitory_true()))
  {
    // Re-test condition in critical area.
    if (!condition())
      return false;
  }
#ifdef CWDEBUG
  else
    Dout(dc::warning, "Calling EventLoopThread::stop_if(" << condition << ", " << (void*)io_watcher << ")");
#endif

  ev_io_stop(EV_A_ io_watcher);
  return true;
}

namespace {
SingletonInstance<EventLoopThread> dummy __attribute__ ((__unused__));
} // namespace

} // namespace evio
