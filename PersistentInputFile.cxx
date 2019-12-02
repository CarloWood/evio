/**
 * evio -- A cwm4 git submodule for adding support for buffered, iostream oriented, epoll based I/O.
 *
 * @file
 * @brief Definition of class PersistentInputFile.
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

#include "sys.h"
#include "PersistentInputFile.h"

namespace evio {

void PersistentInputFile::closed(int& allow_deletion_count)
{
  DoutEntering(dc::evio, "PersistentInputFile::closed({" << allow_deletion_count << "}) [" << this << ']');
  if (is_watched())
  {
    rm_watch();
    ++allow_deletion_count;     // It is now no longer needed to keep this object alive, see below.
  }
}

// Read thread.
void PersistentInputFile::read_returned_zero(int& CWDEBUG_ONLY(allow_deletion_count))
{
  DoutEntering(dc::evio, "PersistentInputFile::read_returned_zero({" << allow_deletion_count << "}) [" << this << ']');
  {
    // Lock m_state and then make sure that no new data was appended to the file in the meantime.
    state_t::wat state_w(m_state);
    char buf[1];
    int rlen;
    while ((rlen = ::read(m_fd, buf, 1)) == -1 && errno == EAGAIN)
      ;
    if (AI_UNLIKELY(rlen == 1))
      throw OneMoreByte{buf[0]};
    stop_input_device(state_w);
  }
  // Add an inotify watch for modification of the corresponding path (if not already watched).
  if (!is_watched() && !open_filename().empty())
  {
    add_watch(open_filename().c_str(), IN_MODIFY);
    CWDEBUG_ONLY(int count =) inhibit_deletion(); // Keep this object alive because the call to add_watch registered m_inotify as callback object.
                                                        // Object is kept alive until a call to allow_deletion() caused by a call to PersistentInputFile::closed().
    Dout(dc::io, "Incremented ref count (now " << (count + 1) << ") of this device [" << this << ']');
  }
}

} // namespace evio
