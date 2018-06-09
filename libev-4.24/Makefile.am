AUTOMAKE_OPTIONS = foreign

VERSION_INFO = 4:0:0

EXTRA_DIST = LICENSE libev.m4 \
	     ev_vars.h ev_wrap.h \
	     ev_epoll.c

include_HEADERS = ev.h

lib_LTLIBRARIES = libev.la

libev_la_SOURCES = ev.c
libev_la_LDFLAGS = -version-info $(VERSION_INFO)
