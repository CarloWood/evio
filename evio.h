// evio -- Event Driven I/O support.
//
//! @file
//! @brief Definition of evio::events_type and declaration of libev functions and structs.
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

void ev_unref();        // Cause ev_run() to exit even though a device is still running.
void ev_ref();          // Theoretically needed to balance ev_unref() calls (before stopping said devices).

enum {
  EVRUN_NOWAIT = 1, /* do not block/wait */
//  EVRUN_ONCE   = 2  /* block *once* only */
};

enum {
//  EVBREAK_CANCEL = 0, /* undo unloop */
  EVBREAK_ONE    = 1, /* unloop once */
  EVBREAK_ALL    = 2  /* unloop all loops */
};

enum {
  EVFLAG_NOENV     = 0x01000000U, /* do NOT consult environment */
};

enum {
  EVBACKEND_EPOLL   = 0x00000004U, /* linux */
};

struct ev_io
{
};

unsigned int ev_pending_count();
void ev_invoke_pending();
int ev_requested_break();
typedef void (*ev_loop_callback)();
void ev_set_invoke_pending_cb(ev_loop_callback invoke_pending_cb);
int ev_default_loop(unsigned int flags);
void ev_set_userdata(void* data);
void ev_set_loop_release_cb(void (*release)(), void (*acquire)());
void ev_io_start(ev_io* w);
void ev_io_stop(ev_io* w);
void* ev_userdata();
int ev_run(int flags);
