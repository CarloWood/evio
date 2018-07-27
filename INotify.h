// evio -- Event Driven I/O support.
//
//! @file
//! @brief Declaration of class File.
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

#pragma once

#include "evio/Device.h"
#include "utils/Singleton.h"
#include "threadsafe/aithreadsafe.h"
#include "threadsafe/AIReadWriteSpinLock.h"
#include <vector>
#include <utility>

namespace evio {

class INotify;

//=============================================================================
//
// class INotifyDevice
//
// Base class for an inotify device.
//
// SYNOPSIS
//
// This class implements a wrapper around inotify_init1(2), inotify_add_watch(2)
// and inotify_rm_watch(2) to watch other filedescriptors for events.
// See inotify(7) for more details.

class INotifyDevice : public ReadInputDevice, public Singleton<INotifyDevice>, public virtual IOBase
{
  friend_Instance;
 private:
  INotifyDevice() : ReadInputDevice(nullptr), m_len_so_far(0) { m_name_len = -1; }
  ~INotifyDevice() { }
  INotifyDevice(INotifyDevice const&) = delete;

  size_t m_len_so_far;
  union { char m_buf[4]; int32_t m_name_len; };

  // Map watch filedescriptors to their corresponding INotify objects.
  using wd_to_inotify_map_type = std::vector<std::pair<int, INotify*>>;
  // Use AIReadWriteSpinLock because we'll be doing vastly more read locks than write locks.
  using wd_to_inotify_map_ts = aithreadsafe::Wrapper<wd_to_inotify_map_type, aithreadsafe::policy::ReadWrite<AIReadWriteSpinLock>>;
  wd_to_inotify_map_ts m_wd_to_inotify_map;

  static wd_to_inotify_map_type::const_iterator get_inotify_obj(wd_to_inotify_map_ts::crat const& wd_to_inotify_map_r, int wd);

 protected:
  size_t end_of_msg_finder(char const* new_data, size_t rlen) override;
  void decode(MsgBlock msg) override;

 public:
  int add_watch(char const* pathname, uint32_t mask, INotify* obj);
  void rm_watch(int wd);
};

class INotify
{
 private:
   int m_wd;    // The watch descriptor (or -1 if none).

 protected:
  //---------------------------------------------------------------------------
  // Constructors
  //

  // Default constructor. Use `watch' to associate the object with a file.
  INotify() : m_wd(-1) { }

  //---------------------------------------------------------------------------
  // Public methods
  //

  // Associate this object with `pathname'. The events to be monitored for pathname
  // are  specified  in  the  mask bit-mask argument.
  // See inotify(7) for a description of the bits that can be set in mask.
  //
  void add_watch(char const* pathname, uint32_t mask)
  {
    m_wd = INotifyDevice::instance().add_watch(pathname, mask, this);
  }

  // Disassociate this object its pathname, if any.
  void rm_watch()
  {
    if (m_wd != -1)
    {
      INotifyDevice::instance().rm_watch(m_wd);
      m_wd = -1;
    }
  }
};

} // namespace evio
