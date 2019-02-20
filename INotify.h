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

#include "debug.h"
#include <vector>
#include <utility>
#include <sys/inotify.h>

namespace evio {

class INotifyDecoder;

//=============================================================================
//
// class INotify
//
// Wrapper around an inotify watch descriptor for a given path name.
//

class INotify
{
 private:
   int m_wd;    // The watch descriptor (or -1 if none).

 public:
  //---------------------------------------------------------------------------
  // Constructors
  //

  // Default constructor. Use `add_watch' to associate the object with a file.
  INotify() : m_wd(-1) { }

 private:
  static int add_watch(char const* pathname, uint32_t mask, INotify* inotify);
  static void rm_watch(int wd);

 public:
  //---------------------------------------------------------------------------
  // Public methods
  //

  // Associate this object with `pathname'. The events to be monitored for pathname
  // are  specified  in  the  mask bit-mask argument.
  // See inotify(7) for a description of the bits that can be set in mask.
  //
  // Returns true when a pointer to this object was added to INotifyDevice::m_wd_to_inotify_map.
  //
  void add_watch(char const* pathname, uint32_t mask)
  {
    // Call rm_watch() before calling add_watch() again.
    ASSERT(m_wd == -1);
    m_wd = add_watch(pathname, mask, this);
  }

  // Disassociate this object from its pathname, if any.
  // Returns true when were actually watching something (when a previous call to add_watch was successful).
  void rm_watch()
  {
    // Please call is_watched() before calling this function.
    ASSERT(is_watched());
    rm_watch(m_wd);
    m_wd = -1;
  }

  bool is_watched() const
  {
    return m_wd != -1;
  }

 protected:
  friend INotifyDecoder;
  virtual void event_occurred(inotify_event const* event) = 0;
};

} // namespace evio
