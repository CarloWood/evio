# Determine the malloc overhead.
CW_SYS_MALLOC_OVERHEAD

# evio depends on utils, threadsafe and threadpool.
m4_if(cwm4_submodule_dirname, [], [m4_append_uniq_w([CW_SUBMODULE_SUBDIRS], [utils threadsafe threadpool], [ ])])

LIBEVIO_CXXFLAGS='$(MATRIXSSL_CFLAGS)'
LIBEVIO_LIBS='${top_builddir}/evio/libevio.la $(MATRIXSSL_LIBS)'

AC_SUBST([LIBEVIO_CXXFLAGS])
AC_SUBST([LIBEVIO_LIBS])

m4_if(cwm4_submodule_dirname, [], [m4_append_uniq([CW_SUBMODULE_SUBDIRS], cwm4_submodule_basename, [ ])])
m4_append_uniq([CW_SUBMODULE_CONFIG_FILES], cwm4_quote(cwm4_submodule_path[/Makefile]), [ ])
m4_append_uniq([CW_SUBMODULE_CONFIG_FILES], cwm4_quote(cwm4_submodule_path[/protocol/Makefile]), [ ])

# Add configuration options for evio.

AC_ARG_ENABLE(debug-buffers,
    [  --enable-debug-buffers  enable debugging of the dynamic blocks stream buffer.],
    cw_config_debug_buffers=$enableval, cw_config_debug_buffers=no)

AC_SUBST([CW_CONFIG_DEBUGBUFFERS])
CW_CONFIG_DEBUGBUFFERS=undef

if test "$cw_config_debug_buffers" = yes; then
  CW_CONFIG_DEBUGBUFFERS=define
fi

m4_append_uniq([CW_SUBMODULE_CONFIG_FILES], cwm4_quote(cwm4_submodule_path[/config.h]), [ ])

AH_BOTTOM([#include "evio/config.h"])

dnl vim: filetype=config
