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

namespace evio {

//=============================================================================
//
// class FileDevice
//
// Base class for file Input and Output.
//
// SYNOPSIS
//
// This class implements the common open() and close() of both, input and
// output files.
//
// The reason that reading and writing is kept together until this point is
// that both have a lot in common and the underlaying base classes all deal
// with both input and output, down to the fd_dct which calls select(2)
// (which takes a parameter for both, readable and writable filedescriptors).
//

class FileDevice : public virtual IOBase
{
 protected:
  //---------------------------------------------------------------------------
  // Constructors
  //

  // Default constructor. Use `open' or `IOBase::init' to associate
  // the object with a filedescriptor.
  FileDevice() { }

  //---------------------------------------------------------------------------
  // Public methods
  //

  // Associate this object with a new file `name'.
  // Open this file with mode `mode' and protection `prot'.
  //
  // See `ifstream_dct::ifstream_dct' for a description of the
  // possible values of `mode'.
  void open(char const* filename, int mode, int prot = 0664, int additional_posix_modes = 0);

  // Call the `close' of the base class, which does the real work.
  void close() { ansi_close(); }
};


//=============================================================================
//
// class file_dtct
//
// I/O-FILEBUFfers, base class for I/O-fstream_dct.
//
// SYNOPSIS
//
// Base class for I/O Files. Linkage with the
// input (istream) / output (ostream) buffer.
//

template<class IO>
class File : public FileDevice, public IO
{
public:
  //---------------------------------------------------------------------------
  // Constructors
  //

  File() : IO(new typename IO::buffer_type(IO::default_blocksize_c)) { } // OutputDeviceStream OutputBuffer

#if 0
  // Create a new `file_dtct<IO>' which has a buffer `iobuf_lp'.
  File(typename IO::buffer_type* iobuf_lp)
      {
        Dout(dc::io, "this = " << (void*)this << "; file_dtct(" << (void*)iobuf_lp << ')');
      }

  // Create a new `file_dtct<IO>' which uses the same buffer as some `iotraits_lp'.
  File(typename IO::buflink_type& iotraits_lp)
      {
        Dout(dc::io, "this = " << (void*)this << "; file_dtct(@" << (void*)&iotraits_lp << ')');
      }
#endif

  // Constructors that combine the above three two `open':

#if 0
  // Create a new `file_dtct<IO>' which has a buffer `iobuf_lp' and open a file.
  file_dtct(typename IO::buffer_ct* iobuf_lp, char const* name_lp, int mode_lp = IO::mode, int prot_lp = 0664) :
      dbbuf_fd_dtct<IO>(iobuf_lp), file_dbct()
      {
        Dout(dc::io, "this = " << (void*)this << "; file_dtct(" << (void*)iobuf_lp << ", \"" << name_lp << "\", " << mode_lp << ", " << std::oct << prot_lp << ')');
        open(name_lp, mode_lp, prot_lp);
      }

  // Create a new `file_dtct<IO>' which uses the same buffer as some `iotraits_lp' and open a file.
  file_dtct(typename IO::buflinkT& iotraits_lp, char const* name_lp, int mode_lp = IO::mode, int prot_lp = 0664) :
      dbbuf_fd_dtct<IO>(iotraits_lp), file_dbct()
      {
        Dout( dc::io, "this = " << (void*)this << "; file_dtct(@" << (void*)&iotraits_lp << ", \"" << name_lp << "\", " << mode_lp << ", " << std::oct << prot_lp << ')');
        open(name_lp, mode_lp, prot_lp);
      }

  file_dtct(char const* name_lp, int mode_lp = IO::mode, int prot_lp = 0664) :
      dbbuf_fd_dtct<IO>(NEW( typename IO::buffer_ct(IO::default_blocksize_c, UINT_MAX, UINT_MAX) )), file_dbct()
      {
        Dout(dc::io, "this = " << (void*)this << "; file_dtct(" << name_lp << "\", " << mode_lp << ", " << std::oct << prot_lp << ')');
        open(name_lp, mode_lp, prot_lp);
      }
    // Allocate a buffer ourselfs and open a file.
#endif

public:
  //---------------------------------------------------------------------------
  // Public methods
  //

  // Call the `open' of the base class, which does the real work.
  void open(char const* name, int mode = IO::mode, int prot = 0664) { return FileDevice::open(name, mode, prot); }

  // Call the `close' of the base class, which does the real work.
  using FileDevice::close;
};


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
#if 0
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
