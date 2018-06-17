AM_CPPFLAGS = -iquote $(top_builddir) -iquote $(top_srcdir) -iquote $(top_srcdir)/cwds

SUBDIRS = libev-4.24

noinst_LTLIBRARIES = libevio.la

SOURCES = EventLoopThread.cxx \
	  EventLoopThread.h \
	  FileDescriptor.cxx \
	  FileDescriptor.h

libevio_la_SOURCES = ${SOURCES}
libevio_la_CXXFLAGS = -std=c++11 @LIBCWD_R_FLAGS@ -pthread
libevio_la_LIBADD = ../statefultask/libstatefultask.la ../threadsafe/libthreadsafe.la ../utils/libutils_r.la @LIBCWD_R_LIBS@
