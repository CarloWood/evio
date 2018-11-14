// evio -- Event Driven I/O support.
//
//! @file
//! @brief Declaration of class RefCountReleaser.
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
#include "utils/AIRefCount.h"   // Needed for intrusive_ptr_release(AIRefCount*)

#if defined(CWDEBUG) && !defined(DOXYGEN)
NAMESPACE_DEBUG_CHANNELS_START
extern channel_ct io;           // IO specific debug output.
NAMESPACE_DEBUG_CHANNELS_END
#endif

namespace evio {

struct RefCountReleaser
{
 private:
  AIRefCount* m_ptr;

 public:
  void execute()
  {
    if (m_ptr)
    {
      Dout(dc::io, "Decrementing ref count of device " << (void*)m_ptr << " to " << (m_ptr->ref_count() - 1));
      intrusive_ptr_release(m_ptr);
    }
    m_ptr = nullptr;
  }
  RefCountReleaser() : m_ptr(nullptr) { }
  ~RefCountReleaser() { execute(); }
  RefCountReleaser(RefCountReleaser&& releaser) { ASSERT(!m_ptr); m_ptr = releaser.m_ptr; releaser.m_ptr = nullptr; }
  RefCountReleaser& operator=(RefCountReleaser&& releaser) { ASSERT(!m_ptr); m_ptr = releaser.m_ptr; releaser.m_ptr = nullptr; return *this; }
  RefCountReleaser& operator+=(RefCountReleaser&& releaser)
  {
    if (m_ptr && releaser.m_ptr) { ASSERT(m_ptr == releaser.m_ptr); execute(); }
    m_ptr = releaser.m_ptr;
    releaser.m_ptr = nullptr;
    return *this;
  }
  void operator=(AIRefCount* ptr) { ASSERT(!m_ptr); m_ptr = ptr; }
  void reset() { m_ptr = nullptr; }
  operator bool() const { return m_ptr; }
};

} // namespace evio
