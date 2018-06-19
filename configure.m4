# Include tests needed for libev.
m4_include([evio/libev-4.24/libev.m4])

# Determine the malloc overhead.
CW_SYS_MALLOC_OVERHEAD

# evio depends on statefultask (it uses AIThreadPool).
m4_if(cwm4_submodule_dirname, [], [m4_append_uniq([CW_SUBMODULE_SUBDIRS], statefultask, [ ])])

m4_if(cwm4_submodule_dirname, [], [m4_append_uniq([CW_SUBMODULE_SUBDIRS], cwm4_submodule_basename, [ ])])
m4_append_uniq([CW_SUBMODULE_CONFIG_FILES], cwm4_quote(cwm4_submodule_path[/Makefile]), [ ])
m4_append_uniq([CW_SUBMODULE_CONFIG_FILES], cwm4_quote(cwm4_submodule_path[/libev-4.24/Makefile]), [ ])

# We are on linux, so we should have epoll.
# Do not include the select and poll backends to keep the library small.
AC_DEFINE([EV_USE_POLL], 0, [Don't use poll(2)])
AC_DEFINE([EV_USE_SELECT], 0, [Don't use select(2)])
# Disable as many watchers as possible.
AC_DEFINE([EV_FORK_ENABLE], 0, [No support for fork watchers])
AC_DEFINE([EV_PREPARE_ENABLE], 0, [No prepare watchers])
AC_DEFINE([EV_IDLE_ENABLE], 0, [No idle watchers])
AC_DEFINE([EV_CHECK_ENABLE], 0, [No check watchers])
# We only need one loop.
AC_DEFINE([EV_MULTIPLICITY], 0, [Don't support multiple loops])
AC_DEFINE([EV_COMPAT3], 0, [No backwards compatibility needed])
