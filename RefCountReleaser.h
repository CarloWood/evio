/**
 * evio -- A cwm4 git submodule for adding support for buffered, iostream oriented, epoll based I/O.
 *
 * @file
 * @brief Declaration of class RefCountReleaser.
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

#include "debug.h"
#include "utils/macros.h"

#if defined(CWDEBUG) && !defined(DOXYGEN)
NAMESPACE_DEBUG_CHANNELS_START
extern channel_ct io;           // IO specific debug output.
NAMESPACE_DEBUG_CHANNELS_END
#endif

namespace evio {

class FileDescriptor;

struct RefCountReleaser         // TestSuite: test_RefCountReleaser.h
{
 private:
  FileDescriptor* m_device;
  int m_allow_deletion_count;

 public:
  RefCountReleaser() : m_device(nullptr), m_allow_deletion_count(0) { }
  RefCountReleaser(FileDescriptor* device, int allow_deletion_count) : m_device(device), m_allow_deletion_count(allow_deletion_count) { ASSERT(allow_deletion_count >= 0); }
  ~RefCountReleaser() { if (m_allow_deletion_count) execute(m_device, m_allow_deletion_count); }
  RefCountReleaser(RefCountReleaser const&) = delete;
  RefCountReleaser& operator=(RefCountReleaser const&) = delete;

  static void execute(FileDescriptor* device, int allow_deletion_count);

  RefCountReleaser(RefCountReleaser&& releaser) : m_device(releaser.m_device), m_allow_deletion_count(releaser.m_allow_deletion_count)
  {
    DoutEntering(dc::notice, "RefCountReleaser::RefCountReleaser({RefCountReleaser&&:" << releaser.m_device << ", " << releaser.m_allow_deletion_count << "})");
    releaser.m_allow_deletion_count = 0;
  }

  RefCountReleaser& operator=(RefCountReleaser&& releaser)
  {
    DoutEntering(dc::notice, "RefCountReleaser::operator=({RefCountReleaser&&:" << releaser.m_device << ", " << releaser.m_allow_deletion_count << "})");
    ASSERT(!m_allow_deletion_count);
    m_device = releaser.m_device;
    m_allow_deletion_count = releaser.m_allow_deletion_count;
    releaser.m_allow_deletion_count = 0;
    return *this;
  }

#if 0
  RefCountReleaser& operator+=(RefCountReleaser&& releaser)
  {
    DoutEntering(dc::notice, "RefCountReleaser::operator+=({RefCountReleaser&&:" << releaser.m_device << ", " << releaser.m_allow_deletion_count <<
        "}) [with this m_allow_deletion_count = " << m_allow_deletion_count << "]");
    ASSERT(m_device == releaser.m_device);
    m_allow_deletion_count += releaser.m_allow_deletion_count;
    releaser.m_allow_deletion_count = 0;
    return *this;
  }
  void add(int allow_deletion_count COMMA_DEBUG_ONLY(FileDescriptor* device))
  {
    DoutEntering(dc::notice, "RefCountReleaser::add(" << allow_deletion_count << ", " << device << ")");
    ASSERT(m_device == device);
    m_allow_deletion_count += allow_deletion_count;
  }
#endif
  void operator=(FileDescriptor* device)
  {
    DoutEntering(dc::notice, "RefCountReleaser::operator=(" << device << ")");
    ASSERT(!m_device || m_device == device);
    m_device = device;
    ++m_allow_deletion_count;
  }
  operator bool() const { return m_allow_deletion_count > 0; }

  // The following is used by the test suite.
  void execute()
  {
    // This must be the same code as in the destructor.
    this->~RefCountReleaser();
    // But needs to reset m_allow_deletion_count of course.
    m_allow_deletion_count = 0;
  }
  void reset()
  {
    m_device = nullptr;
    m_allow_deletion_count = 0;
  }
};

} // namespace evio
