/**
 * evio -- A cwm4 git submodule for adding support for buffered, iostream oriented, epoll based I/O.
 *
 * @file
 * @brief Declaration of class RawInputDevice.
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
#include "evio/StreamBuf-threads.h"

namespace utils {
class FuzzyCondition;
}

namespace evio {

class RawInputDevice : public virtual FileDescriptor
{
 protected:
  RawInputDevice();
  ~RawInputDevice();

 public:
  //---------------------------------------------------------------------------
  // Public accessors:
  //

  // Returns true if the input device is registered with epoll.
  template<typename ThreadType>
  utils::FuzzyBool is_active(ThreadType) const
  {
    constexpr bool get_thread = std::is_base_of<GetThread, ThreadType>::value;
    constexpr bool put_thread = std::is_base_of<PutThread, ThreadType>::value;
    static_assert(get_thread || put_thread || std::is_same<AnyThread, ThreadType>::value,
                  "May only be called with ThreadType is SingleThread, AnyThread, GetThread or PutThread.");

    bool is_active = state_t::crat(m_state)->m_flags.is_active_input_device();

    // Basically we need the following table to hold:
    //  Currently active  SingleThread    AnyThread       GetThread       PutThread
    //       yes          WasTrue         WasTrue         WasTrue         WasTrue
    //        no          False           WasFalse        False           WasFalse
    //
    return is_active ? fuzzy::WasTrue : (get_thread ? fuzzy::False : fuzzy::WasFalse);
  }

 protected:
  // Override base class virtual functions.
  void init_input_device(state_t::wat const& state_w) override;

  // Close input device. Return true if the device has now completely closed (dead).
  bool close_input_device(int& allow_deletion_count, state_t::wat const& state_w);

 protected:
  bool start_input_device(state_t::wat const& state_w, utils::FuzzyCondition const& condition);
  void start_input_device(state_t::wat const& state_w);
  bool stop_input_device(state_t::wat const& state_w, utils::FuzzyCondition const& condition);
  void stop_input_device(state_t::wat const& state_w);
  bool disable_input_device(state_t::wat const& state_w, utils::FuzzyCondition const& condition);
  void disable_input_device(state_t::wat const& state_w);
  void enable_input_device();
  void remove_input_device(int& allow_deletion_count, state_t::wat const& state_w);

  [[gnu::always_inline]] void stop_input_device() { stop_input_device(state_t::wat(m_state)); }
  [[gnu::always_inline]] void disable_input_device() { disable_input_device(state_t::wat(m_state)); }
  [[gnu::always_inline]] void remove_input_device(int& allow_deletion_count) { remove_input_device(allow_deletion_count, state_t::wat(m_state)); }
 public: // ONLY public because StreamBuf::do_restart_input_device_if_needed() needs to call this :/
  [[gnu::always_inline]] void start_input_device() { start_input_device(state_t::wat(m_state)); }

 public:
  void close_input_device(int& allow_deletion_count) override;

  RefCountReleaser close_input_device()
  {
    int allow_deletion_count = 0;
    close_input_device(allow_deletion_count);
    return {this, allow_deletion_count};
  }
};

} // namespace evio
