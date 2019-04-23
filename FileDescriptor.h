// evio -- Event Driven I/O support.
//
//! @file
//! @brief Declaration of FileDescriptor.
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

#include "utils/AIRefCount.h"
#include "RefCountReleaser.h"
#include <cstdint>
#include <atomic>

#if defined(CWDEBUG) && !defined(DOXYGEN)
NAMESPACE_DEBUG_CHANNELS_START
extern channel_ct evio;
NAMESPACE_DEBUG_CHANNELS_END
#endif

namespace evio {

// Return true if fd is a valid open filedescriptor.
bool is_valid(int fd);

class FileDescriptor : public AIRefCount
{
 protected:
  using flags_t = uint32_t;
  static int constexpr disabled_shft = 2;
  static int constexpr open_shft = 4;
  static flags_t constexpr FDS_W                   = 0x80000000;
  static flags_t constexpr FDS_R                   = 0x40000000;
  static flags_t constexpr FDS_RW                  = FDS_R | FDS_W;
  static flags_t constexpr FDS_W_DISABLED          = 0x20000000;        // Must be FDS_W >> disabled_shft.
  static flags_t constexpr FDS_R_DISABLED          = 0x10000000;        // Must be FDS_R >> disabled_shft.
  static flags_t constexpr FDS_W_OPEN              = 0x08000000;        // Must be FDS_W >> open_shft.
  static flags_t constexpr FDS_R_OPEN              = 0x04000000;        // Must be FDS_R >> open_shft.
  static flags_t constexpr FDS_SAME                = 0x02000000;
  static flags_t constexpr FDS_DEAD                = 0x00800000;
  static flags_t constexpr INTERNAL_FDS_DONT_CLOSE = 0x00400000;
#ifdef CWDEBUG
  static flags_t constexpr FDS_DEBUG               = 0x00100000;
#endif

  std::atomic<flags_t> m_flags;

 public:
  // Return true if this object is a base class of OutputDevice.
  bool writable_type() const { return m_flags & FDS_W; }

  // Return true if this object is a base class of InputDevice.
  bool readable_type() const { return m_flags & FDS_R; }

  // Returns true if this object is a writable device.
  bool is_writable() const { return (m_flags & (FDS_W|FDS_W_DISABLED|FDS_W_OPEN|FDS_DEAD)) == (FDS_W|FDS_W_OPEN); }

  // Returns true if this object is a readable device.
  bool is_readable() const { return (m_flags & (FDS_R|FDS_R_DISABLED|FDS_R_OPEN|FDS_DEAD)) == (FDS_R|FDS_R_OPEN); }

  // Return true if this object is marked that it should not close its fd.
  bool dont_close() const { return m_flags & INTERNAL_FDS_DONT_CLOSE; }

  // Return true if this object has at least one open filedescriptor.
  bool is_open() const { return m_flags & ((m_flags & FDS_RW) >> open_shft); }

  // Return true if this object is marked as having an open fd for writing.
  bool is_open_w() const { return m_flags & FDS_W_OPEN; }

  // Return true if this object is marked as having an open fd for reading.
  bool is_open_r() const { return m_flags & FDS_R_OPEN; }

  // Returns true if this object is not associated with a working fd.
  bool is_dead() const { return m_flags & FDS_DEAD; }

  // Returns true if this object is disabled at this moment.
  bool is_disabled() const { return m_flags & ((m_flags & FDS_RW) >> disabled_shft); }

#ifdef CWDEBUG
  // Returns true if this object is used for debug output.
  // If it is, then no new debug output will be produced by the kernel while handling it.
  bool is_debug_channel() const { return m_flags & FDS_DEBUG; }
#endif

  // (Re)Initialize the Device using filedescriptor fd.
  void init(int fd);

 private:
  // At least one of these must be overridden to initialize the appropriate device(s).
  // Both are called by init().
  virtual void init_input_device(int UNUSED_ARG(fd)) { }
  virtual void init_output_device(int UNUSED_ARG(fd)) { }

 protected:
  FileDescriptor() : m_flags(0) { }

  // Queries.
  // Called to obtain the fd that init_input_device() was called with if that actually did initialize an input device; otherwise -1 is returned.
  virtual int get_input_fd() const { return -1; }
  // Called to obtain the fd that init_output_device() was called with if that actually did initialize an output device; otherwise -1 is returned.
  virtual int get_output_fd() const { return -1; }

  // Called by close(). These will be overridden by InputDevice and/or OutputDevice.
  virtual RefCountReleaser close_input_device() { return RefCountReleaser(); }
  virtual RefCountReleaser close_output_device() { return RefCountReleaser(); }

  RefCountReleaser close()
  {
    RefCountReleaser need_allow_deletion;
    need_allow_deletion = close_input_device();
    need_allow_deletion += close_output_device();
    return need_allow_deletion;
  }

  // Events.
  // The filedescriptor(s) of this device were just closed (close_fds() was called).
  // If INTERNAL_FDS_DONT_CLOSE is set then the fd(s) weren't really closed, but this method is still called.
  // When we get here the object is also marked as FDS_DEAD.
  virtual RefCountReleaser closed() { return RefCountReleaser(); }

#if CWDEBUG
  friend std::ostream& operator<<(std::ostream& os, FileDescriptor const* fdptr)
  {
    return os << "FD:" << static_cast<void const*>(fdptr);
  }
#endif
};

// Convenience function to create devices.
template<typename DeviceType, typename... ARGS, typename = typename std::enable_if<std::is_base_of<FileDescriptor, DeviceType>::value>::type>
boost::intrusive_ptr<DeviceType> create(ARGS&&... args)
{
  DoutEntering(dc::evio, "evio::create<" << libcwd::type_info_of<DeviceType>().demangled_name() << ", ARGS...>(ARGS&&...)");
  DeviceType* device = new DeviceType(std::forward<ARGS>(args)...);
  AllocTag2(device, "Created with evio::create");
  Dout(dc::evio, "Returning device pointer " << (void*)device << " [" << device << "].");
  return device;
}

} // namespace evio
