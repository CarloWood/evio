# Include tests needed for libev.
m4_include([evio/libev-4.24/libev.m4])

m4_if(cwm4_submodule_dirname, [], [m4_append_uniq([CW_SUBMODULE_SUBDIRS], cwm4_submodule_basename, [ ])])
m4_append_uniq([CW_SUBMODULE_CONFIG_FILES], cwm4_quote(cwm4_submodule_path[/Makefile]), [ ])
m4_append_uniq([CW_SUBMODULE_CONFIG_FILES], cwm4_quote(cwm4_submodule_path[/libev-4.24/Makefile]), [ ])

# We are on linux, so we should have epoll.
# Do not include the select and poll backends to keep the library small.
AC_DEFINE([EV_USE_POLL], 0, [Don't use poll(2)])
AC_DEFINE([EV_USE_SELECT], 0, [Don't use select(2)])
AC_DEFINE([EV_MULTIPLICITY], 0, [Don't support multiple loops])
