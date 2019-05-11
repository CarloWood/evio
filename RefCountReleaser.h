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
#include "utils/AIRefCount.h"
#include "utils/macros.h"

#if defined(CWDEBUG) && !defined(DOXYGEN)
NAMESPACE_DEBUG_CHANNELS_START
extern channel_ct io;           // IO specific debug output.
NAMESPACE_DEBUG_CHANNELS_END
#endif

namespace evio {

struct RefCountReleaser         // TestSuite: test_RefCountReleaser.h
{
 private:
  AIRefCount* m_ptr;

 public:
  void execute()
  {
    if (m_ptr)
    {
      // Cancel the call to inhibit_deletion().
      CWDEBUG_ONLY(int count =) m_ptr->allow_deletion();
      Dout(dc::io, "Decremented ref count of device " << (void*)m_ptr << " to " << (count - 1));
    }
    m_ptr = nullptr;
  }
  RefCountReleaser() : m_ptr(nullptr) { }
  ~RefCountReleaser() { execute(); }
  RefCountReleaser(RefCountReleaser&& releaser) : m_ptr(releaser.m_ptr) { releaser.m_ptr = nullptr; }
  RefCountReleaser& operator=(RefCountReleaser&& releaser) { ASSERT(!m_ptr); m_ptr = releaser.m_ptr; releaser.m_ptr = nullptr; return *this; }
  RefCountReleaser& operator+=(RefCountReleaser&& releaser)
  {
    if (AI_LIKELY(releaser.m_ptr))
    {
      if (m_ptr)
      {
        ASSERT(m_ptr == releaser.m_ptr);
        ASSERT(m_ptr->unique().is_momentary_false()); // If momentary false than fuzzy::False because neither this nor releaser will call execute() before the next line.
        // It is safe to call this because it won't delete the underlaying object (m_ptr);
        // it is from now on kept alive by this RefCountReleaser.
        releaser.execute();
      }
      else
      {
        // Move releaser to *this.
        m_ptr = releaser.m_ptr;
        releaser.m_ptr = nullptr;
      }
    }
    return *this;
  }
  void operator=(AIRefCount* ptr) { ASSERT(!m_ptr); m_ptr = ptr; }
  void reset() { m_ptr = nullptr; }
  operator bool() const { return m_ptr; }
};

} // namespace evio
