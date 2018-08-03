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

template<class INPUTDEVICE>
class PersistentInputFile : public File<INPUTDEVICE>, private INotify
{
 public:
  using File<INPUTDEVICE>::File;

 private:
  // Override IOBase::closed() event to remove any inotify watch when it exists.
  IOBase::RefCountReleaser closed() override;

  // Override InputDevice::read_returned_zero().
  IOBase::RefCountReleaser read_returned_zero() override;

  // Override method of INotify.
  void event_occurred(inotify_event const* event) override
  {
    if ((event->mask & IN_MODIFY))
      INPUTDEVICE::start_input_device();
  }
};

template<class INPUTDEVICE>
IOBase::RefCountReleaser PersistentInputFile<INPUTDEVICE>::closed()
{
  IOBase::RefCountReleaser releaser;
  DoutEntering(dc::evio, "PersistentInputFile<" << type_info_of<INPUTDEVICE>().demangled_name() << ">::closed()");
  if (is_watched())
  {
    rm_watch();
    releaser = this;
  }
  return releaser;
}

template<class INPUTDEVICE>
IOBase::RefCountReleaser PersistentInputFile<INPUTDEVICE>::read_returned_zero()
{
  DoutEntering(dc::evio, "PersistentInputFile<" << type_info_of<INPUTDEVICE>().demangled_name() << ">::read_returned_zero()");
  IOBase::RefCountReleaser releaser = INPUTDEVICE::stop_input_device();
  // Add an inotify watch for modification of the corresponding path (if not already watched).
  if (!is_watched() && !FileDevice::open_filename().empty())
  {
    if (add_watch(FileDevice::open_filename().c_str(), IN_MODIFY))
    {
      if (releaser)
        intrusive_ptr_add_ref(this);    // Keep this object alive because the above call registered m_inotify as callback object.
      releaser.reset();
      Dout(dc::io, "Incremented ref count (now " << IOBase::ref_count() << ") of this device [" << (void*)static_cast<IOBase*>(this) << ']');
    }
  }
  return releaser;
}

} // namespace evio
