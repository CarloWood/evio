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

#include "InputDevice.h"
#include "OutputDevice.h"
#include <fcntl.h>

namespace evio {

//=============================================================================
//
// class File
//
// SYNOPSIS
//
// This class implements the common open() and close() of both, input and
// output files.
//

class File : public InputDevice, public OutputDevice
{
 private:
  std::string m_filename;       // The name of the opened file.

 public:
  //---------------------------------------------------------------------------
  // Constructors
  //

  // Default constructor.
  File() { DoutEntering(dc::evio, "File::File() [" << this << "]"); }

  //---------------------------------------------------------------------------
  // Public manipulators.
  //

  // Associate this object with an existing and open file `fd'.
  void init(int fd, std::string const& filename);

  // Associate this object with a new file `filename'.
  // Open this file with mode `mode' and protection `prot'.
  //
  // See https://en.cppreference.com/w/cpp/io/ios_base/openmode
  // for the possible values of `mode'.
  void open(std::string const& filename, std::ios_base::openmode mode, int prot = 0664, int additional_posix_modes = O_CLOEXEC);

  // Call the `close' of the base class, which does the real work.
  void close() { m_filename.clear(); FileDescriptor::close(); }

  //---------------------------------------------------------------------------
  // Accessors.
  //

  // Returns the currently open filename (empty if not open).
  std::string const& open_filename() const { return m_filename; }
};

#if 0
//=============================================================================
//
// class std_dtct
//
// Standard IO base class
//
// SYNOPSIS
//
// Base class for standard I/O.
//
template<class IO>
class stdio_dtct : public dbbuf_fd_dtct<IO>, virtual public fd_dct {
private:
  void init(int fd_lp)
      {
#ifdef CWDEBUG
	if (fd_lp < 0 || fd_lp > 2)
	  __LibcwDoutFatal( dc::core, "Invalid stdio filedescriptor (" << fd_lp << ')' );
        if (!IO::fd_type)
	  __LibcwDoutFatal( dc::core, "stdio_dtct<IO>: IO must be either readable or writable" );
        if ((fd_lp == 0 && !(IO::fd_type|FDS_R)) || fd_lp != 0 && !(IO::fd_type|FDS_W))
	  __LibcwDoutFatal( dc::core, "stdio_dtct<IO>: IO and filedescriptor don't match" );
#endif
	add(fd_lp, IO::fd_type|FDS_BLOCKING);
      }

public:
  //---------------------------------------------------------------------------
  // Constructors
  //

  stdio_dtct(typename IO::buffer_ct* iobuf_lp, int fd_lp) : dbbuf_fd_dtct<IO>(iobuf_lp)
      {
        __LibcwDout( dc::io, "this = " << (void*)this << "; stdio_dtct(" << (void*)iobuf_lp << ", " << fd_lp << ')' );
	init(fd_lp);
      }
    // Create a new `stdio_dtct<IO>' which has a buffer`iobuf_lp' and uses filedescriptor `fd_lp'.

  stdio_dtct(typename IO::buflinkT& iotraits_lp, int fd_lp) : dbbuf_fd_dtct<IO>(iotraits_lp)
      {
        __LibcwDout( dc::io, "this = " << (void*)this << "; stdio_dtct(@" << (void*)&iotraits_lp << ", " << fd_lp << ')' );
	init(fd_lp);
      }
    // Create a new `stdio_dtct<IO>' which uses the same buffer as some `iotraits_lp' and uses filedescriptor `fd_lp'.

  // Added for convience:

  stdio_dtct(int fd_lp) : dbbuf_fd_dtct<IO>(NEW( typename IO::buffer_ct(IO::default_blocksize_c, UINT_MAX, UINT_MAX) ))
      {
        __LibcwDout( dc::io, "this = " << (void*)this << "; stdio_dtct(" << fd_lp << ")" );
        init(fd_lp);
      }
    // Allocate a buffer ourselfs, use filedescriptor `fd_lp'.
};
#endif

} // namespace evio
