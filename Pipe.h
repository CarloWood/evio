/**
 * evio -- A cwm4 git submodule for adding support for buffered, iostream oriented, epoll based I/O.
 *
 * @file
 * @brief Declaration of class Pipe.
 *
 * @Copyright (C) 2019  Carlo Wood.
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

#include "evio/InputDevice.h"
#include "evio/OutputDevice.h"

namespace evio {

class Pipe;

class PipeReadEnd : public InputDevice
{
  friend class Pipe;
  PipeReadEnd() = default;
  void init(int fd0, bool make_fd_non_blocking);
};

class PipeWriteEnd : public OutputDevice
{
  friend class Pipe;
  PipeWriteEnd() = default;
  void init(int fd1, bool make_fd_non_blocking);
};

class Pipe
{
 private:
  boost::intrusive_ptr<PipeReadEnd> m_pipe_read_end;
  boost::intrusive_ptr<PipeWriteEnd> m_pipe_write_end;

 public:
  Pipe();

  boost::intrusive_ptr<PipeReadEnd> take_read_end()
  {
    // Only call pipe_read_end() once.
    ASSERT(m_pipe_read_end);
    return std::move(m_pipe_read_end);
  }

  boost::intrusive_ptr<PipeWriteEnd> take_write_end()
  {
    // Only call pipe_write_end() once.
    ASSERT(m_pipe_write_end);
    return std::move(m_pipe_write_end);
  }
};

} // namespace evio
