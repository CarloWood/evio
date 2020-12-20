/**
 * evio -- A cwm4 git submodule for adding support for buffered, iostream oriented, epoll based I/O.
 *
 * @file
 * @brief Declaration of class OutputDevice.
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

#pragma once

#include "FileDescriptor.h"
#include "StreamBuf.h"
#include "Protocol.h"

namespace utils {
class FuzzyCondition;
} // namespace utils

namespace evio {

class Source;
class OutputBuffer;
class LinkBufferPlus;

class OutputDevice : public virtual FileDescriptor
{
 public:
  // The remote peer closed the connection.
  void hup(int& allow_deletion_count, int UNUSED_ARG(fd)) override { close_output_device(allow_deletion_count); }

  // Event: fd is writable.
  //
  // This default implementation writes data from the buffer to the fd until
  // 1) the buffer is empty, or
  // 2) write(2) wrote less than the number of bytes passed to it, or
  // 3) write(2) returned an error other than EAGAIN or EINTR, or
  // 4) EAGAIN != EWOULDBLOCK and EAGAIN happens twice in a row, or
  // 5) write(2) returned EINTR caused by SIGPIPE.
  // When write(2) returns an error other then EINTR (or when EINTR was caused by SIGPIPE),
  // EAGAIN or EWOULDBLOCK it calls the virtual function write_error, see below.
  void write_to_fd(int& allow_deletion_count, int fd) override;

  // This default implementation `close's the object (which removes it).
  virtual void write_error(int& allow_deletion_count, int UNUSED_ARG(err)) { close(allow_deletion_count); }

 private:
  using disable_is_flushing_t = aithreadsafe::Wrapper<bool, aithreadsafe::policy::Primitive<std::mutex>>;
  disable_is_flushing_t m_disable_is_flushing;

  // List of InputDevice objects that have FDS_R_CLOSE set.
  // For this to work, ONLY set/unset FDS_R_CLOSE through calls to InputDevice::close_on_exit(bool)!
  using w_close_list_t = aithreadsafe::Wrapper<std::vector<boost::intrusive_ptr<OutputDevice>>, aithreadsafe::policy::Primitive<std::mutex>>;
  static w_close_list_t s_w_close_list;

 protected:
  //---------------------------------------------------------------------------
  // The output buffer
  //

#if defined(__clang__) && __clang_major__ <= 6
  // clang++ 6.x and lower erroneously assumes that this class is always aligned like FileDescriptor (64),
  // but that is not true when this class is used in multiple inheritance. So, force the alignment that
  // clang++ assumes.
  alignas(16)
#endif
  Source* m_source;                     // A pointer to the source object that creates the output buffer for us (has knowledge of the Protocol).
  OutputBuffer* m_obuffer;              // A pointer to the output buffer.
#ifdef DEBUGDEVICESTATS
  size_t m_sent_bytes;
#endif

 protected:
  // The default condition just checks if the output device is not already active.
  // When that is used, you are responsible to not call start_output_device when
  // (in the current thread) the device is already active, also in the case of
  // races (aka, there are no possible races allowed).
  // Only the producer thread will start an output device automatically. Which means
  // that either the caller *is* the producer thread, or is certain the device is
  // stopped and no producer thread is running -- aka nobody is writing to the device
  // when this function is being called.
  friend class Source;
  bool start_output_device(state_t::wat const& state_w, utils::FuzzyCondition const& condition);
  void start_output_device(state_t::wat const& state_w);
  bool stop_output_device(int& allow_deletion_count, utils::FuzzyCondition const& condition);
  void stop_output_device(int& allow_deletion_count);
  [[gnu::always_inline]] inline bool stop_not_flushing_output_device(state_t::wat const& state_w, utils::FuzzyCondition const& condition);
  [[gnu::always_inline]] inline void stop_not_flushing_output_device(state_t::wat const& state_w);

  void remove_output_device(int& allow_deletion_count, state_t::wat const& state_w);
  void disable_output_device();
  void enable_output_device();

  bool start_output_device(utils::FuzzyCondition const& condition)
  {
    state_t::wat state_w(m_state);
    // This test is just to catch a race condition where this device is being closed at the same time.
    if (AI_UNLIKELY(!state_w->m_flags.is_writable()))
      return false;
    return start_output_device(state_w, condition);
  }
  void start_output_device()
  {
    state_t::wat state_w(m_state);
    // This test is just to catch a race condition where this device is being closed at the same time.
    if (AI_LIKELY(state_w->m_flags.is_writable()))
      start_output_device(state_w);
  }
  [[gnu::always_inline]] void remove_output_device(int& allow_deletion_count) { remove_output_device(allow_deletion_count, state_t::wat(m_state)); }

 protected:
  OutputDevice();
  ~OutputDevice();

  // Disallow copy constructing.
  OutputDevice(OutputDevice const&) = delete;

 public:
  //---------------------------------------------------------------------------
  // Public accessors:
  //

#if 0
  // Supposed to be used for passing it to other device constructors.
  Buf2Dev* rddbbuf() const { return m_obuffer; }
#endif

#ifdef DEBUGDEVICESTATS
  size_t sent_bytes() const { return m_sent_bytes; }
#endif

  // Returns true if the output device is registered with epoll.
  template<typename ThreadType>
  utils::FuzzyBool is_active(ThreadType) const
  {
    constexpr bool get_thread = std::is_base_of<GetThread, ThreadType>::value;
    constexpr bool put_thread = std::is_base_of<PutThread, ThreadType>::value;
    static_assert(get_thread || put_thread || std::is_same<AnyThread, ThreadType>::value,
                  "May only be called with ThreadType is SingleThread, AnyThread, GetThread or PutThread.");

    bool is_active = state_t::crat(m_state)->m_flags.is_active_output_device();

    // Basically we need the following table to hold:
    //  Currently active  SingleThread    AnyThread       GetThread       PutThread
    //       yes          WasTrue         WasTrue         WasTrue         WasTrue
    //        no          False           WasFalse        WasFalse        False
    //
    return is_active ? fuzzy::WasTrue : (put_thread ? fuzzy::False : fuzzy::WasFalse);
  }

  void restart_if_non_active()
  {
    // This function should be called only from Buf2Dev::flush and OutputDevice::enable_output_device, and therefore be an output device.
    state_t::wat state_w(m_state);
    ASSERT(state_w->m_flags.is_output_device());
    if (state_w->m_flags.is_writable() && !state_w->m_flags.is_active_output_device())
      start_output_device(state_w);
  }

 public:
  //---------------------------------------------------------------------------
  // Public manipulators:
  //

  template<typename... Args>
  void set_source(Source& output_device_ptr, Args... output_create_buffer_arguments);

  template<typename INPUT_DEVICE>
  void set_source(boost::intrusive_ptr<INPUT_DEVICE> const& ptr,
      size_t requested_minimum_block_size, size_t buffer_full_watermark, size_t max_alloc = std::numeric_limits<size_t>::max());

  template<typename INPUT_DEVICE>
  void set_source(boost::intrusive_ptr<INPUT_DEVICE> const& ptr,
      size_t requested_minimum_block_size)
  {
    set_source(ptr, requested_minimum_block_size, 8 * StreamBuf::round_up_minimum_block_size(requested_minimum_block_size));
  }

  RefCountReleaser flush_output_device();
  RefCountReleaser close_output_device()
  {
    int allow_deletion_count = 0;
    close_output_device(allow_deletion_count);
    return {this, allow_deletion_count};
  }
  RefCountReleaser stop_output_device()
  {
    int allow_deletion_count = 0;
    stop_output_device(allow_deletion_count);
    return {this, allow_deletion_count};
  }

  void close_on_exit(bool auto_close = true)
  {
    Dout(dc::evio, "close_on_exit(" << std::boolalpha << auto_close << ") [" << this << "]");
    w_close_list_t::wat w_close_list_w(s_w_close_list);
    state_t::wat state_w(m_state);
    // Only call this method with alternating values of `auto_close`, starting with `true`.
    ASSERT(state_w->m_flags.is_w_close() != auto_close);
    if (auto_close)
    {
      w_close_list_w->emplace_back(this);
      state_w->m_flags.set_w_close();
    }
    else
    {
      for (auto iter = w_close_list_w->begin(); iter != w_close_list_w->end(); ++iter)
        if (iter->get() == this)
        {
          w_close_list_w->erase(iter);
          break;
        }
      state_w->m_flags.unset_w_close();
    }
  }

  static void flush_close_on_exit()
  {
    DoutEntering(dc::evio, "flush_close_on_exit()");
    w_close_list_t::wat w_close_list_w(s_w_close_list);
    for (auto&& ptr : *w_close_list_w)
      ptr->close_output_device();
    w_close_list_w->clear();
  }

 protected:
  // Called from the streambuf associated with this device when pubsync() is called on it.
  friend class StreamBufProducer;
  virtual int sync();

 private:
  // Called by the second set_source above.
  inline void set_source(LinkBufferPlus* link_buffer);

  // Override base class virtual functions.
  void init_output_device(state_t::wat const& state_w) override;
  void close_output_device(int& allow_deletion_count) override final;
};

} // namespace evio

#include "OutputStream.h"
#include "InputDevice.h"

namespace evio {

void OutputDevice::set_source(LinkBufferPlus* link_buffer)
{
  m_obuffer = static_cast<OutputBuffer*>(link_buffer->as_Buf2Dev());
  m_source = link_buffer;
}

template<typename... Args>
void OutputDevice::set_source(Source& output_device_ptr, Args... output_create_buffer_arguments)
{
#ifdef CWDEBUG
  LibcwDoutScopeBegin(LIBCWD_DEBUGCHANNELS, ::libcwd::libcw_do, dc::evio)
  LibcwDoutStream << "Entering OutputDevice::set_source<";
  LibcwDoutStream << join(", ", libcwd::type_info_of<Args>().demangled_name()...) << ">(" <<
    (void*)&output_device_ptr << join_more(", ", output_create_buffer_arguments...) << ") [" << this << ']';
  LibcwDoutScopeEnd;
  NAMESPACE_DEBUG::Indent __cwds_debug_indent(DEBUGCHANNELS::dc::evio.is_on() ? 2 : 0);
#endif
  m_source = &output_device_ptr;
  m_obuffer = m_source->create_buffer(this, output_create_buffer_arguments...);
}

template<typename INPUT_DEVICE>
void OutputDevice::set_source(boost::intrusive_ptr<INPUT_DEVICE> const& ptr, size_t requested_minimum_block_size, size_t buffer_full_watermark, size_t max_alloc)
{
  DoutEntering(dc::evio, "OutputDevice::set_source<" << libcwd::type_info_of<INPUT_DEVICE>().demangled_name() << ">([" << &*ptr << "], " << requested_minimum_block_size << ", " << buffer_full_watermark << ", " << max_alloc << ") [" << this << ']');

  // We need to create a link buffer and use it to link the following two devices.
  InputDevice* input_device = ptr.get();
  OutputDevice* output_device = this;

  // Create the link buffer.
  LinkBufferPlus* link_buffer = new LinkBufferPlus(input_device, output_device, StreamBuf::round_up_minimum_block_size(requested_minimum_block_size), buffer_full_watermark, max_alloc);

  // Initialize the output device to read from the link buffer.
  output_device->set_source(link_buffer);

  // Initialize the input device to write to the link buffer.
  input_device->set_sink(link_buffer);
}

} // namespace evio
