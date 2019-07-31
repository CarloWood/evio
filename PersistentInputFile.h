// evio -- Event Driven I/O support.
//
//! @file
//! @brief Declaration of class PersistentInputFile.
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

#include "File.h"
#include "INotify.h"

namespace evio {

class PersistentInputFile : public File, private INotify
{
 private:
  // Override FileDescriptor::closed() event to remove any inotify watch when it exists.
  void closed(int& allow_deletion_count) override;

 public:
  using VT_type = File::VT_type;
  #define VT_evio_PersistentInputFile VT_evio_File

  struct VT_impl : File::VT_impl
  {
    // Override InputDevice::read_returned_zero().
    static void read_returned_zero(int& allow_deletion_count, InputDevice* self);

    // Virtual table of PersistentInputFile.
    static constexpr VT_type VT VT_evio_PersistentInputFile;
  };

  // Make a deep copy of VT_ptr.
  VT_type* clone_VT() override { return VT_ptr.clone(this); }

  utils::VTPtr<PersistentInputFile, File> VT_ptr;

 protected:
  // Override method of INotify.
  void event_occurred(inotify_event const* event) override
  {
    if ((event->mask & IN_MODIFY))
    {
      state_t::wat state_w(m_state);
      if (state_w->m_flags.is_readable())       // Do not (re)start the input device when it was closed in the mean time.
        start_input_device(state_w);
    }
  }

 public:
  PersistentInputFile() : VT_ptr(this) { }
};

} // namespace evio
