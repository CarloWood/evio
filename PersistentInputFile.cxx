// evio -- Event Driven I/O support.
//
//! @file
//! @brief Definition of class PersistentInputFile.
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
#include "PersistentInputFile.h"

namespace evio {

RefCountReleaser PersistentInputFile::closed()
{
  RefCountReleaser releaser;
  DoutEntering(dc::evio, "PersistentInputFile::closed() [" << this << ']');
  if (is_watched())
  {
    rm_watch();
    releaser = this;
  }
  return releaser;
}

// Read thread.
RefCountReleaser PersistentInputFile::read_returned_zero()
{
  DoutEntering(dc::evio, "PersistentInputFile::read_returned_zero() [" << this << ']');
  RefCountReleaser releaser = stop_input_device();
  // Add an inotify watch for modification of the corresponding path (if not already watched).
  if (!is_watched() && !open_filename().empty())
  {
    if (add_watch(open_filename().c_str(), IN_MODIFY))
    {
      if (releaser)
        inhibit_deletion();     // Keep this object alive because the above call registered m_inotify as callback object.
      releaser.reset();
      Dout(dc::io, "Incremented ref count (now " << FileDescriptor::ref_count() << ") of this device [" << this << ']');
    }
  }
  return releaser;
}

} // namespace evio
