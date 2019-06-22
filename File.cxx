// evio -- Event Driven I/O support.
//
//! @file
//! @brief Definition of class FileDevice.
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
#include "File.h"
#include "utils/AIAlert.h"
#include "EventLoopThread.h"
#include <ios>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

namespace evio {

void File::init(int fd, std::string const& filename)
{
  m_filename = filename;
  state_t::wat(m_state)->m_flags.set_regular_file();
  FileDescriptor::init(fd);
}

void File::open(std::string const& filename, std::ios_base::openmode mode, int prot, int additional_posix_modes)
{
  using std::ios_base;

  int posix_mode;

  if ((mode & ios_base::app))
    mode |= ios_base::out;

  // Call input() and/or output() before calling open().
  ASSERT(m_ibuffer || m_obuffer);

  if ((mode & (ios_base::in|ios_base::out)) == 0)
  {
    if (m_ibuffer)
      mode |= ios_base::in;
    if (m_obuffer)
      mode |= ios_base::out;
  }
#ifdef CWDEBUG
  else
  {
    // If at least one of ios_base::in or ios_base::out is specified, it
    // must match the buffers that we have.
    ASSERT((m_ibuffer == nullptr) == !(mode & ios_base::in));   // Call input() before calling open().
    ASSERT((m_obuffer == nullptr) == !(mode & ios_base::out));  // Call output() before calling open().
  }
#endif

  if ((mode & (ios_base::in|ios_base::out)) == (ios_base::in|ios_base::out))
  {
    posix_mode = O_RDWR;
  }
  else if ((mode & ios_base::out))
    posix_mode = O_WRONLY;
  else
    posix_mode = O_RDONLY;

  // Do not call open() on a device that is already initialized with a fd (see FileDescriptor::init) or call close() first.
  ASSERT(!state_t::rat(m_state)->m_flags.is_open());

  // Meant to be used for things like O_CLOEXEC, O_DIRECTORY, O_DSYNC, O_EXCL, O_NOATIME, O_NOFOLLOW, O_NONBLOCK, O_SYNC, O_TMPFILE, ...
  posix_mode |= additional_posix_modes;

  if ((mode & ios_base::trunc) || mode == ios_base::out)
    posix_mode |= O_TRUNC;
  if ((mode & ios_base::app))
    posix_mode |= O_APPEND;
  if (!(mode & ios_base::in))
    posix_mode |= O_CREAT;

  Dout(dc::system|continued_cf, "open(\"" << filename << "\", " << NAMESPACE_DEBUG::PosixMode(posix_mode) << ", " << std::oct << prot << std::dec << ") = ");
  int fd = ::open(filename.c_str(), posix_mode, prot);
  Dout(dc::finish|cond_error_cf(fd < 0), fd);

  if (fd < 0)
    THROW_ALERTE("open([FILENAME], [POSIX_MODE], [PROT]) = -1", AIArgs("[FILENAME]", filename)("[POSIX_MODE]", posix_mode)("[PROT]", prot));

  if ((mode & (ios_base::ate|ios_base::app)))
  {
    if (lseek(fd, 0, SEEK_END) == (off_t)-1)
    {
      int errn = errno;
      ::close(fd);
      THROW_ALERTC(errn, "lseek([FD], 0, SEEK_END) = -1", AIArgs("[FD]", fd));
    }
  }

  // Success.
  init(fd, filename);
  state_t::wat state_w(m_state);
  if (m_ibuffer)
    start_input_device(state_w);
  if (m_obuffer)
  {
    // This condition assumes we are the PutThread (no other thread is writing
    // to this buffer). This is correct since we only started the input device
    // and no other thread but the EventLoopThread even knows about this
    // device/buffer yet, as we just initialized it.
    utils::FuzzyCondition condition_not_empty([this]{
          return !m_obuffer->StreamBufProducer::buffer_empty();
        });
    if (condition_not_empty.is_momentary_true())
      start_output_device(state_w, condition_not_empty);
  }
}

} // namespace evio
