/**
 * evio -- A cwm4 git submodule for adding support for buffered, iostream oriented, epoll based I/O.
 *
 * @file
 * @brief Definition of class EventLoopThread.
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
#include "EventLoopThread.h"
#include "InputDevice.h"
#include "OutputDevice.h"
#include "INotify.h"
#include "threadpool/AIThreadPool.h"
#include "utils/cpu_relax.h"
#include "utils/AIAlert.h"
#include "debug.h"
#include <chrono>
#ifdef CWDEBUG
#include "utils/debug_ostream_operators.h"
#endif

#ifndef DEBUG_EPOLL_PWAIT_DELAY_MICROSECONDS
#define DEBUG_EPOLL_PWAIT_DELAY_MICROSECONDS 0
#endif

std::string epoll_events_str(uint32_t events);

namespace evio {

// Singleton initialization.
void EventLoopThread::init(AIQueueHandle handler)
{
  DoutEntering(dc::evio, "EventLoopThread::init(" << handler << ')');
  m_handler = handler;

  // Create the thread running the loop around epoll_pwait.
  m_event_thread = std::thread(&EventLoopThread::emain, &EventLoopThread::instance());

  // Wait till we're actually running.
  while (!m_running)
    cpu_relax();
}

EventLoopThread::~EventLoopThread()
{
  // Call EventLoopThread::instance().terminate() before leaving main().
  ASSERT(!m_event_thread.joinable());

  if (m_epoll_fd != -1)        // Was init() called?
  {
//    if (m_terminate)
//      ev_ref();
    if (::close(m_epoll_fd) == -1)
      Dout(dc::warning|error_cf, "EventLoopThread::~EventLoopThread: close(" << m_epoll_fd << ") = -1");
  }
}

//static
struct epoll_event EventLoopThread::s_events[maxevents];

//static
void EventLoopThread::s_wakeup_handler(int)
{
  EventLoopThread& self(instance());
  Dout(dc::evio(self.m_terminate != not_yet), "EventLoopThread::s_wakeup_handler: self.m_active = " << self.m_active);
  if (self.m_terminate == forced || (self.m_terminate == cleanly && self.m_active == 0))
  {
    Dout(dc::evio, "EventLoopThread::s_wakeup_handler: Stopping event loop thread because m_active == 0.");
    self.m_stop_running.store(true, std::memory_order_relaxed);
  }
}

// EventLoopThread main function.
void EventLoopThread::emain()
{
  Debug(NAMESPACE_DEBUG::init_thread("EventLoopThr"));
  Dout(dc::evio, "Entering EventLoopThread::emain() [no indentation]");

  Dout(dc::system|continued_cf, "epoll_create1(EPOLL_CLOEXEC) = ");
  m_epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  Dout(dc::finish|cond_error_cf(m_epoll_fd == -1), m_epoll_fd);
  if (m_epoll_fd == -1)
    DoutFatal(dc::fatal, "Failed to obtain an epoll file descriptor.");

  // Prepare a sigset for the signal(s) that we use to wake up epoll_pwait in epoll_sigmask.
  // Unblock those signals.
  sigset_t epoll_sigmask;
  utils::Signals::unblock(&epoll_sigmask, m_epoll_signum, &s_wakeup_handler);

  // The current signal mask is the mask that we want to use while inside epoll_pwait too.
  // It will be copied to pwait_sigmask before entering epoll_pwait.
  sigset_t pwait_sigmask;
  sigemptyset(&pwait_sigmask);

  m_stop_running = false;
  m_running = true;

  AIThreadPool& thread_pool(AIThreadPool::instance());
  auto queues_access = thread_pool.queues_read_access();
  auto& queue = thread_pool.get_queue(queues_access, m_handler);

  int all_threads_finished = 0;

  // MAIN LOOP
  while (AI_LIKELY(all_threads_finished >= 0))
  {
    // Before entering epoll_pwait, block the signal(s) that can change our wake-up flags.
    sigprocmask(SIG_BLOCK, &epoll_sigmask, &pwait_sigmask);
    int nfds;
    do
    {
      // While m_epoll_signum is blocked, deal with a wake-up and see if we must terminate.
      if (AI_UNLIKELY(m_stop_running.load(std::memory_order_relaxed)))
      {
        if (all_threads_finished)
        {
          garbage_collection();
          nfds = -1;
          all_threads_finished = -1;    // Really terminate.
          break;
        }
        // Enter epoll_pwait() one more time.
        // Wait for all threads to be finished.
#if 0
        // FIXME - is this possible?
        while ()
        {
        }
#else
        Dout(dc::evio|continued_cf, "Sleeping 20 milliseconds in the hope that then all threads have finished... ");
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        Dout(dc::finish, "done.");
#endif
        all_threads_finished = 1;
        Dout(dc::system|continued_cf|flush_cf, "epoll_pwait(20ms) = ");
#ifdef CWDEBUG
        utils::InstanceTracker<FileDescriptor>::for_each([](FileDescriptor const* p){ Dout(dc::system, p << ": " << p->get_fd() << ", " << p->get_flags()); });
#endif
        nfds = epoll_pwait(m_epoll_fd, s_events, maxevents, 20, &pwait_sigmask);
        Dout(dc::finish|cond_error_cf(nfds == -1), nfds);
        break;  // Go to top of main loop.
      }

      Dout(dc::system|continued_cf|flush_cf, "epoll_pwait() = ");
#ifdef CWDEBUG
      utils::InstanceTracker<FileDescriptor>::for_each([](FileDescriptor const* p){ Dout(dc::system, p << ": " << p->get_fd() << ", " << p->get_flags()); });
#endif
      nfds = epoll_pwait(m_epoll_fd, s_events, maxevents, -1, &pwait_sigmask);
      Dout(dc::finish|cond_error_cf(nfds == -1), nfds);
    }
    while (nfds == -1 && errno == EINTR);
    // Unblock the signal(s) that can change our wake-up flags again by restoring the old set.
    sigprocmask(SIG_SETMASK, &pwait_sigmask, NULL);

#if DEBUG_EPOLL_PWAIT_DELAY_MICROSECONDS
    std::this_thread::sleep_for(std::chrono::microseconds(DEBUG_EPOLL_PWAIT_DELAY_MICROSECONDS));
#endif

    // Handle the returned event(s) for each fd.
    while (nfds > 0)
    {
      epoll_event& event(s_events[--nfds]);

      // This is the only place where bits in m_pending_events are set.
      FileDescriptor* device = static_cast<FileDescriptor*>(event.data.ptr);
      uint32_t const already_pending_events = device->test_and_set_pending_events(event.events);

      uint32_t const not_already_pending_input_events = EPOLLIN & ~already_pending_events;
      uint32_t const not_already_pending_output_events = (already_pending_events & (EPOLLOUT|EPOLLHUP|EPOLLERR)) ? 0 : (EPOLLOUT|EPOLLHUP|EPOLLERR);

      uint32_t input_events = event.events & not_already_pending_input_events;
      uint32_t output_events = event.events & not_already_pending_output_events;

#ifdef CWDEBUG
      uint32_t const suppressed_events = event.events & ~(input_events|output_events);
      if (suppressed_events)
        Dout(dc::evio,
            "epoll_pwait event(s) " << epoll_events_str(suppressed_events) << " of fd " << device << " ignored because "
            "the event(s) " << epoll_events_str(event.events & already_pending_events) << " is/are already being handled by the thread pool.");
#endif

      if ((input_events|output_events) == 0)
        continue;

      // We have new events that need handling.
      Dout(dc::evio, "epoll_pwait new event(s): " << epoll_events_str(input_events|output_events));

      // Because hup_event() and err_event() are usually no-OPs handle them in the EventLoopThread if there isn't also an EPOLLOUT event to handle.
      if (AI_UNLIKELY((output_events & ~EPOLLOUT)) && !(output_events & EPOLLOUT))
      {
        int allow_deletion_count = 0;
        if ((output_events & EPOLLHUP))
          device->hup_event(allow_deletion_count);
        else if ((output_events & EPOLLERR))            // Only call err_event when EPOLLHUP isn't set.
          device->err_event(allow_deletion_count);
        else
          DoutFatal(dc::core, "output_events = " << std::hex << output_events);
        device->allow_deletion(allow_deletion_count);
        // Since this thread is the only thread that sets bits, and the bits we just set only involved EPOLLHUP and/or EPOLLERR,
        // there are no pending output events left.
        device->clear_pending_events(EPOLLOUT|EPOLLHUP|EPOLLERR);
        output_events = 0;
        if (!input_events)
        {
          // Next device.
          continue;
        }
      }

      // Because the threads of the thread pool run asynchronously, make sure the
      // device object won't be deleted while we're processing it.
      if (AI_UNLIKELY(device->inhibit_deletion(DEBUG_ONLY(false)) == 0))
      {
        // If inhibit_deletion returned zero then this device was marked for deletion in between
        // returning from epoll_pwait and the call to test_and_set_pending_events.
        // In that case we may not increment the reference count because decrementing it later
        // would delete it twice (not to mention that we could access it after it was already
        // deleted because this device is now in the m_needs_deletion_list list and will be deleted
        // at the end of this loop.
        Dout(dc::evio, "Ignoring events on " << device << " because the device is already added to the m_needs_deletion_list!");
        device->AIRefCount::allow_deletion(true);
        // Reset the bits that we just set - because we're not going to handle them after all.
        device->clear_pending_events(event.events & ~already_pending_events);
        // Next device.
        continue;
      }

      bool two_types_of_events = input_events && output_events;
      if (two_types_of_events)
        device->inhibit_deletion();

      // Queue the events for processing by the thread pool.
      CWDEBUG_ONLY(bool queue_was_full = false;)
      {
        bool queue_full;
        auto queue_access = queue.producer_access();
        do
        {
          int const queue_length = queue_access.length();
          if ((queue_full = queue_length == queue.capacity()))
          {
            // Queue is full! Wait for a broadcast.
            Dout(dc::warning(!queue_was_full), "Thread pool queue " << m_handler << " is full! Now no longer handling any socket etc. I/O until this is resolved.");
            Debug(queue_was_full = true);
            queue_access.wait();                                // Wait until queue_access.notify_one() is called.
          }
          else
          {
            // Actually add the events to the thread pool queue for handling.
            Dout(dc::warning(queue_was_full), "Queue is no longer full; resuming I/O.");

            if (input_events)   // EPOLLIN
            {
              Dout(dc::evio, "Queuing I/O event EPOLLIN for " << device << " in thread pool queue " << m_handler);
              // Note that device is a pointer (8 bytes) and events and m_epoll_fd are both [u]int32_t (4 bytes each),
              // so that we capture 16 bytes in the lambe. DO NOT CAPTURE MORE, as that would start to allocate
              // memory with malloc.
              queue_access.move_in([device, epoll_fd = m_epoll_fd COMMA_CWDEBUG_ONLY(input_events)](){
                Dout(dc::evio, "Beginning of handling event " << epoll_events_str(input_events) << " for " << device << ".");
                int allow_deletion_count = 1;                     // Balance with the call to inhibit_deletion(false) above.
                try
                {
                  device->read_event(allow_deletion_count);
                }
                catch (AIAlert::Error const& error)
                {
                  Dout(dc::warning, error);
                  device->close(allow_deletion_count);
                }
                device->clear_pending_input_event(epoll_fd);
                device->allow_deletion(allow_deletion_count);
                return false;
              });

              if (AI_UNLIKELY((queue_full = queue_length - 1 == queue.capacity())) && output_events)
              {
                input_events = 0;       // Already queued.
                continue;
              }
            }

            if (output_events)
            {
              Dout(dc::evio, "Queuing I/O event " << epoll_events_str(output_events) << " for " << device << " in thread pool queue " << m_handler);
              queue_access.move_in([device, output_events, epoll_fd = m_epoll_fd](){
                Dout(dc::evio, "Beginning of handling event " << epoll_events_str(output_events) << " for " << device << ".");
                int allow_deletion_count = 1;                     // Balance with the call to inhibit_deletion(false) above.
                uint32_t pending_events = output_events;
                if (AI_LIKELY(output_events == EPOLLOUT))
                {
                  device->write_event(allow_deletion_count);
                  device->clear_pending_output_events(epoll_fd, pending_events);
                }
                if (AI_UNLIKELY(pending_events & ~EPOLLOUT))
                {
                  if ((pending_events & EPOLLHUP))
                    device->hup_event(allow_deletion_count);
                  else if ((pending_events & EPOLLERR))           // Only call err_event when EPOLLHUP isn't set.
                    device->err_event(allow_deletion_count);
                  else if ((pending_events & ~(EPOLLOUT|EPOLLHUP|EPOLLERR)))
                    DoutFatal(dc::core, "events = " << std::hex << pending_events);
                  device->clear_pending_output_events(epoll_fd, pending_events);
                }
                device->allow_deletion(allow_deletion_count);
                return false;
              });
            }
          }
        }
        while (queue_full);
      }
      queue.notify_one();
      if (two_types_of_events)
        queue.notify_one();
    }
    if (AI_UNLIKELY(all_threads_finished < 0))
      OutputDevice::flush_close_on_exit();
    garbage_collection();
  }

  m_running = false;

  // Deinit.
  ASSERT(m_terminate == forced || m_active == 0);
  INotify::tear_down();
  utils::Signals::block_and_unregister(m_epoll_signum);
  Dout(dc::system|continued_cf, "close(" << m_epoll_fd << ") = ");
  CWDEBUG_ONLY(int res =) ::close(m_epoll_fd);
  Dout(dc::finish|cond_error_cf(res == -1), res);
  m_epoll_fd = -1;
  // Keep the value of m_epoll_signum!

#ifdef CWDEBUG
  if (m_terminate == cleanly)
  {
    // Sanity check.
    //
    // It is a bad thing when not all FileDescriptor objects are dead, because that
    // can lead to events that access memory that might no longer be allocated once
    // we return from the EventLoopThread main loop.
    //
    // If you assert here then you have a bug in your program: before leaving the
    // main loop (destructing evio::EventLoop) do one of the following:
    //
    // In the case of an OutputDevice (FDS_W_OPEN is set), either call close_output_device()
    // (or close()) to forcefully close the device (e.g. if it is in an error state),
    // or call flush_output_device() once you're done writing to it.
    // Alternatively call close_on_exit() after initialization; this will automatically
    // (forcefully) close the output device when the main loop is terminated. This can
    // be used when it is not possible to call flush_output_device() because it is
    // not known when the last data was written to the device.
    //
    // In the case of an InputDevice (FDS_R_OPEN is set), call close_input_device()
    // (or close()) once you have read everything you need to read.
    // Calling stop_input_device() is not sufficient.
    bool open_files = false;
    bool unopened_file = false;
    utils::InstanceTracker<FileDescriptor>::for_each([&open_files, &unopened_file](FileDescriptor const* p){
      if (!p->get_flags().is_dead())
      {
        if (!open_files)
        {
          if (p->get_fd() != -1)
          {
            Dout(dc::warning, "Leaving EventLoopThread main loop while not all devices were closed! See comments in EventLoopThread.cxx for more information.");
            open_files = true;
          }
          else
            unopened_file = true;
        }
        Dout(dc::warning, p << ": " << p->get_fd() << ", " << p->get_flags());
      }
    });
    ASSERT(!open_files);
    if (unopened_file)
    {
      Dout(dc::warning, "One or more of the devices has fd -1. This probably means that init was never called (File::open, Socket::connect, ListenSocket::listen, etc)!");
    }
  }
#endif

  m_terminate = not_yet;
  Dout(dc::evio, "Leaving EventLoopThread::emain() [no indentation]");
}

void EventLoopThread::terminate(bool normal_exit)
{
  DoutEntering(dc::evio, "EventLoopThread::terminate(" << normal_exit << ")");
  // This function should only be called from the destructor of EventLoop.
  // Do not call terminate() directly.
  ASSERT(aithreadid::in_main_thread());
  {
    m_terminate = normal_exit ? cleanly : forced;
    bump_terminate();
  }
  if (m_event_thread.joinable())
  {
    Dout(dc::evio|continued_cf|flush_cf, "Joining m_event_thread... ");
    m_event_thread.join();
    Dout(dc::finish, "joined");
  }
}

#if 0
void EventLoopThread::invoke_pending()
{
  DoutEntering(dc::evio|flush_cf, "EventLoopThread::invoke_pending()");
  std::unique_lock<std::mutex> lock(m_loop_mutex);
  ASSERT(ev_pending_count());
  ev_invoke_pending();

  // Instead of returning control to the ev_run thread immediately, do a
  // quick poll here if there is already more activity in the meantime.
  if (!m_inside_invoke_pending && !ev_requested_break())
  {
    // No recursive calls.
    m_inside_invoke_pending = true;
    // Poll for additional events that might have occurred.
    ev_set_invoke_pending_cb(ev_invoke_pending);                  // Call ev_invoke_pending directly.
    Dout(dc::evio, "Entering ev_run(EVRUN_NOWAIT).");
    ev_run(EVRUN_NOWAIT);
    Dout(dc::evio, "Leaving ev_run(EVRUN_NOWAIT).");
    ev_set_invoke_pending_cb(EventLoopThread::invoke_pending_cb); // Restore normal operation.
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
  if (!ev_pending_count())
    return;

  DoutEntering(dc::evio|flush_cf, "EventLoopThread::handle_invoke_pending()");
  // The lock is already locked when we get here.
  std::unique_lock<std::mutex> lock(m_loop_mutex, std::adopt_lock);
  while (ev_pending_count())
  {
    if (AI_UNLIKELY(m_terminate == forced))
    {
      Dout(dc::evio, "Forced exit from event loop.");
      break;
    }
    else
    {
      AIThreadPool& thread_pool(AIThreadPool::instance());
      //auto const max_duration = std::chrono::milliseconds(64);
      //auto duration = std::chrono::milliseconds(1);
      auto queues_access = thread_pool.queues_read_access();
      auto& queue = thread_pool.get_queue(queues_access, m_handler);
      CWDEBUG_ONLY(bool queue_was_full = false;)
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
  if (AI_UNLIKELY(m_terminate == forced))
    stop_running();
  Dout(dc::evio|flush_cf, "Leaving EventLoopThread::handle_invoke_pending()");
}
#endif

void EventLoopThread::wake_up()
{
  // Test if EventLoopThread::init was called by testing if m_event_thread is joinable.
  if (m_event_thread.joinable())
  {
    Dout(dc::evio, "Sending wake-up signal " << m_epoll_signum);
    pthread_kill(m_event_thread.native_handle(), m_epoll_signum);
  }
  else
    Dout(dc::warning, "Calling EventLoopThread::wake_up(), but event thread is not running. Did you create an EventLoop object at the start of main()?");
}

void EventLoopThread::bump_terminate()
{
  if (m_terminate)
    wake_up();
}

void EventLoopThread::handle_regular_file(FileDescriptorFlags::mask_t active_flag, FileDescriptor* device)
{
  DoutEntering(dc::evio, "EventLoopThread::handle_regular_file(" << active_flag << ", " << device << ")");
  AIThreadPool& thread_pool(AIThreadPool::instance());
  auto queues_access = thread_pool.queues_read_access();
  auto& queue = thread_pool.get_queue(queues_access, m_handler);
  CWDEBUG_ONLY(bool queue_was_full = false;)
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
        Dout(dc::evio, "Queuing call to " << ((active_flag == FileDescriptorFlags::FDS_R_ACTIVE) ? "read_event" : "write_event") << "() in thread pool queue " << m_handler);
        device->inhibit_deletion();
        if (active_flag == FileDescriptorFlags::FDS_R_ACTIVE)
          queue_access.move_in([device](){
              Dout(dc::evio, "Beginning of handling read event for " << device << ".");
              int allow_deletion_count = 1;      // The balance the call to inhibit_deletion above.
              try
              {
                device->read_event(allow_deletion_count);
              }
              catch (AIAlert::Error const& error)
              {
                Dout(dc::warning, error);
                device->close(allow_deletion_count);
              }
              device->allow_deletion(allow_deletion_count);
              return false;
          });
        else // active_flag == FileDescriptorFlags::FDS_W_ACTIVE
          queue_access.move_in([device](){
              Dout(dc::evio, "Beginning of handling write event for " << device << ".");
              int allow_deletion_count = 1;      // The balance the call to inhibit_deletion above.
              device->write_event(allow_deletion_count);
              device->allow_deletion(allow_deletion_count);
              return false;
          });
      }
    }
    while (queue_full);
  }
  queue.notify_one();
}

void EventLoopThread::start(FileDescriptor::state_t::wat const& state_w, FileDescriptorFlags::mask_t active_flag, FileDescriptor* device)
{
  // Create an evio::EventLoop object at the start of main.
  ASSERT(m_epoll_fd != -1);

  // Don't start a device that is disabled.
  if (AI_UNLIKELY(state_w->m_flags.test_disabled(active_flag)))
  {
    Dout(dc::warning, "Calling EventLoopThread::start(" << *state_w << ", " << active_flag << ", " << device << ") for a device that is disabled [" << this << "]");
    return;
  }

  DoutEntering(dc::evio, "EventLoopThread::start(" << *state_w << ", " << active_flag << ", " << device << ")");

  // Don't start a device that is already active.
  if (!state_w->m_flags.test_and_set_active(active_flag))
    return;

  if (!state_w->m_flags.test_inferior(active_flag))
  {
    CWDEBUG_ONLY(int active =) ++m_active;
    Dout(dc::evio, "Incremented m_active to " << active);
  }
  else
    Dout(dc::evio, "Not incrementing m_active because inferior device!");

  if (AI_LIKELY(!state_w->m_flags.is_regular_file()))
  {
    bool needs_adding = state_w->m_flags.test_and_set_added(active_flag);
    if (needs_adding)
    {
      // Increment ref count to stop device from being deleted while being active.
      // Object is kept alive until a call to allow_deletion(), which will be indirectly caused automatically
      // as a result of calling InputDevice::remove_input_device() (or InputDevice::close_input_device,
      // which also calls InputDevice::remove_input_device).
      CWDEBUG_ONLY(int count =) device->inhibit_deletion();
      Dout(dc::io, "Incremented ref count (now " << (count + 1) << ") [" << device << ']');
    }
    device->start_watching(state_w, m_epoll_fd, FileDescriptorFlags::active_to_events(active_flag), needs_adding);
  }
  else
    handle_regular_file(active_flag, device);
}

bool EventLoopThread::start_if(FileDescriptor::state_t::wat const& state_w, utils::FuzzyCondition const& condition, FileDescriptorFlags::mask_t active_flag, FileDescriptor* device)
{
  // Unlikely because you shouldn't call this function if this is the case, see below.
  if (AI_UNLIKELY(condition.is_false()))
  {
    Dout(dc::warning, "Calling EventLoopThread::start_if(" << condition << ", " << active_flag << ", " << device << ") -- don't call start_if when it is sure that it will fail?!");
    return false;
  }

  // Don't start a device that is disabled.
  if (AI_UNLIKELY(state_w->m_flags.test_disabled(active_flag)))
  {
    Dout(dc::warning, "Calling EventLoopThread::start_if(" << condition << ", " << active_flag << ", " << device << ") for a device that is disabled.");
    return true;
  }

  DoutEntering(dc::evio, "EventLoopThread::start_if(" << condition << ", " << active_flag << ", " << device << ")");

  // This should never happen. First of all, for speed up reasons you should only call
  // this function when condition.is_momentary_true(), secondly if the condition would
  // be transitory_false it is nonsense to check the condition again here (we really
  // only want to call start_watching when the condition is true while m_loop_mutex is
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

  // Don't start a device that is already active.
  if (!state_w->m_flags.test_and_set_active(active_flag))
    return true;

  // This is likely because otherwise we shouldn't be using a construction with
  // FuzzyBool / FuzzyCondition in the first place.
  if (AI_LIKELY(condition.is_transitory_true()))
  {
    // Re-test condition in critical area. Note that the critical area is actually the area where m_state is locked
    // which started much sooner. Nevertheless, it is only really required to be locked for testing the condition
    // (again) here. The reason the mutex isn't constantly released before this point is because the code between
    // where it is locked and this point is pretty minimal (just some non-atomic bit fiddling). See README.devices
    // for more information.
    if (condition().is_momentary_false())
    {
      state_w->m_flags.clear_active(active_flag);
      return false;
    }
  }
#ifdef CWDEBUG
  else // is_true()
    Dout(dc::warning, "Calling EventLoopThread::start_if(" << condition << ", " << active_flag <<", " << device << ") -- just call start() without condition?!");
#endif

  if (!state_w->m_flags.test_inferior(active_flag))
  {
    CWDEBUG_ONLY(int active =) ++m_active;
    Dout(dc::evio, "Incremented m_active to " << active);
  }
  else
    Dout(dc::evio, "Not incrementing m_active because inferior device!");

  if (AI_LIKELY(!state_w->m_flags.is_regular_file()))
  {
    bool needs_adding = state_w->m_flags.test_and_set_added(active_flag);
    if (needs_adding)
    {
      // Increment ref count to stop device from being deleted while being active.
      // It is kept alive until a call to allow_deletion().
      CWDEBUG_ONLY(int count =) device->inhibit_deletion();
      Dout(dc::io, "Incremented ref count (now " << (count + 1) << ") [" << device << ']');
    }
    device->start_watching(state_w, m_epoll_fd, FileDescriptorFlags::active_to_events(active_flag), needs_adding);
  }
  else
    handle_regular_file(active_flag, device);

  return true;
}

void EventLoopThread::remove(int& allow_deletion_count, FileDescriptor::state_t::wat const& state_w, FileDescriptorFlags::mask_t active_flag, FileDescriptor* device)
{
  DoutEntering(dc::evio, "EventLoopThread::remove({" << allow_deletion_count << "}, {" << *state_w << "}, " << active_flag << ", " << device << ")");
  bool needs_removal = state_w->m_flags.test_and_clear_added(active_flag) && !state_w->m_flags.is_added();
  bool cleared_active = state_w->m_flags.test_and_clear_active(active_flag);
  if (cleared_active || needs_removal)
  {
    // Regular files don't need removal because they were never added.
    ASSERT(!state_w->m_flags.is_regular_file());
    device->stop_watching(state_w, m_epoll_fd, FileDescriptorFlags::active_to_events(active_flag), needs_removal);
    if (needs_removal)
      ++allow_deletion_count;
  }
  if (cleared_active && !state_w->m_flags.test_inferior(active_flag))
  {
    int active = --m_active;
    Dout(dc::evio, "Decremented m_active to " << active);
    if (active == 0)
      bump_terminate();
  }
}

void EventLoopThread::stop(FileDescriptor::state_t::wat const& state_w, FileDescriptorFlags::mask_t active_flag, FileDescriptor* device)
{
  // Don't stop a device that is already non-active.
  if (!state_w->m_flags.test_and_clear_active(active_flag))
    return;

  if (AI_LIKELY(!state_w->m_flags.is_regular_file()))
    device->stop_watching(state_w, m_epoll_fd, FileDescriptorFlags::active_to_events(active_flag), false);

  if (!state_w->m_flags.test_inferior(active_flag))
  {
    int active = --m_active;
    Dout(dc::evio, "Decremented m_active to " << active);
    if (active == 0)
      bump_terminate();
  }
}

bool EventLoopThread::stop_if(FileDescriptor::state_t::wat const& state_w, utils::FuzzyCondition const& condition, FileDescriptorFlags::mask_t active_flag, FileDescriptor* device)
{
  // Don't stop a device that is already non-active.
  if (!state_w->m_flags.test_and_clear_active(active_flag))
    return true;

  // Unlikely because you shouldn't call this function if this is the case, see below.
  if (AI_UNLIKELY(condition.is_false()))
  {
    Dout(dc::warning, "Calling EventLoopThread::stop_if(" << condition << ", " << active_flag << ", " << device << ") -- don't call stop_if when it is sure that it will fail?!");
    // Revert the clear of the active flag.
    state_w->m_flags.set_active(active_flag);
    return false;
  }

  // See start_if.
  ASSERT(!condition.is_transitory_false());

  // This is likely because otherwise we shouldn't be using a construction with
  // FuzzyBool / FuzzyCondition in the first place.
  if (AI_LIKELY(condition.is_transitory_true()))
  {
    // Re-test condition in critical area. Note that the critical area is actually where m_state is locked (so that began way sooner).
    // In reality, it is only really needed to have that locked right here, before testing the condition again. We're not releasing
    // that lock constantly however, because the code from where it was locked till here is very minimal (just some non-atomic bit fiddling).
    if (condition().is_momentary_false())
    {
      // Revert the clear of the active flag.
      state_w->m_flags.set_active(active_flag);
      return false;
    }
  }
#ifdef CWDEBUG
  else // is_true()
    Dout(dc::warning, "Calling EventLoopThread::stop_if(" << condition << ", " << active_flag << ", " << device << ") -- just call stop() without condition?!");
#endif

  if (AI_LIKELY(!state_w->m_flags.is_regular_file()))
    device->stop_watching(state_w, m_epoll_fd, FileDescriptorFlags::active_to_events(active_flag), false);

  if (!state_w->m_flags.test_inferior(active_flag))
  {
    int active = --m_active;
    Dout(dc::evio, "Decremented m_active to " << active);
    if (active == 0)
      bump_terminate();
  }

  // We are no longer active.
  return true;
}

namespace {
SingletonInstance<EventLoopThread> dummy __attribute__ ((__unused__));
} // namespace

void EventLoopThread::stop_running()
{
  DoutEntering(dc::evio, "EventLoopThread::stop_running()");
  m_stop_running = true;
}

void EventLoopThread::add_needs_deletion(FileDescriptor const* node)
{
  Dout(dc::evio, "EventLoopThread::add_needs_deletion(" << node << ")");
#ifdef CWDEBUG
  if (node->get_flags().is_added())
  {
    Dout(dc::warning, "Adding a device for deletion while that device is still added to epoll! See comments in EventLoopThread.cxx for more information.");
    DoutFatal(dc::core, "A device is still added: " << node << ": " << node->get_fd() << ", " << node->get_flags());
    // Without this core dump it would core in `delete orphan` for the same reason,
    // but the comments there are too general, so I'm catching it here.
  }
#endif
  // Even though node is const -- this is like an initialization of m_next_needs_deletion and therefore we're allowed to change m_next_needs_deletion.
  node->m_next_needs_deletion = m_needs_deletion_list.load(std::memory_order_relaxed);
  while (!m_needs_deletion_list.compare_exchange_weak(node->m_next_needs_deletion, node, std::memory_order_release, std::memory_order_relaxed))
    ;
}

void EventLoopThread::flush_need_deletion()
{
  DoutEntering(dc::evio, "EventLoopThread::flush_need_deletion()");
  FileDescriptor const* head = m_needs_deletion_list.exchange(nullptr, std::memory_order_acquire);
  while (head)
  {
    FileDescriptor const* orphan = head;
    Dout(dc::evio, "Deleting orphan = " << orphan);
    head = orphan->m_next_needs_deletion;
    int allow_deletion_count = 0;
    const_cast<FileDescriptor*>(orphan)->close(allow_deletion_count);   // This will not delete the object (again) because it isn't active.
    ASSERT(allow_deletion_count == 0);
    DEBUG_ONLY(orphan->mark_deleted());
    delete orphan;
#ifdef CWDEBUG
    if (head == orphan)
      DoutFatal(dc::core, "Double deletion detected!");
#endif
  }
}

} // namespace evio
