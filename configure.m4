# Include tests needed for libev.
#m4_include([evio/libev-4.24/libev.m4])

# Determine the malloc overhead.
CW_SYS_MALLOC_OVERHEAD

# Determine the kind of nonblocking sockets that we have.
CW_SYS_NONBLOCK

# Check for GNUTLS.
PKG_CHECK_MODULES([LIBGNUTLS], [gnutls >= 3.5.18])

AC_SUBST([LIBGNUTLS_CFLAGS])
AC_SUBST([LIBGNUTLS_LIBS])

# evio depends on utils, threadsafe and threadpool.
m4_if(cwm4_submodule_dirname, [], [m4_append_uniq_w([CW_SUBMODULE_SUBDIRS], [utils threadsafe threadpool], [ ])])

m4_if(cwm4_submodule_dirname, [], [m4_append_uniq([CW_SUBMODULE_SUBDIRS], cwm4_submodule_basename, [ ])])
m4_append_uniq([CW_SUBMODULE_CONFIG_FILES], cwm4_quote(cwm4_submodule_path[/Makefile]), [ ])
#m4_append_uniq([CW_SUBMODULE_CONFIG_FILES], cwm4_quote(cwm4_submodule_path[/libev-4.24/Makefile]), [ ])

# Add configuration options for evio.

AC_ARG_ENABLE(debug-buffers,
    [  --enable-debug-buffers  enable debugging of the dynamic blocks stream buffer.],
    cw_config_debug_buffers=$enableval, cw_config_debug_buffers=no)

AC_SUBST(CW_CONFIG_DEBUGBUFFERS)
CW_CONFIG_DEBUGBUFFERS=undef

if test "$cw_config_debug_buffers" = yes; then
  CW_CONFIG_DEBUGBUFFERS=define
fi

m4_append_uniq([CW_SUBMODULE_CONFIG_FILES], cwm4_quote(cwm4_submodule_path[/config.h]), [ ])

AH_BOTTOM([#include "evio/config.h"])
