/**
 * evio -- A cwm4 git submodule for adding support for buffered, iostream oriented, epoll based I/O.
 *
 * @file
 * @brief Definition of class Pipe.
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

#include "sys.h"
#include "Pipe.h"
#include "debug.h"
#include <fcntl.h>
#include <unistd.h>

namespace evio {

void PipeReadEnd::init(int fd0, bool make_fd_non_blocking)
{
  fd_init(fd0, make_fd_non_blocking);
  start_input_device();
}

void PipeWriteEnd::init(int fd1, bool make_fd_non_blocking)
{
  fd_init(fd1, make_fd_non_blocking);
}

Pipe::Pipe() : m_pipe_read_end(new PipeReadEnd), m_pipe_write_end(new PipeWriteEnd)
{
  DoutEntering(dc::evio, "Pipe::Pipe()");

  int pipefd[2];
  if (pipe2(pipefd, O_CLOEXEC|O_NONBLOCK) == -1)
    THROW_ALERTE("pipe");

  m_pipe_read_end->init(pipefd[0], false);      // Pass false because we are already non-blocking.
  m_pipe_write_end->init(pipefd[1], false);
}

} // namespace evio
