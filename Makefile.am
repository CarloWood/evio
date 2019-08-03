AM_CPPFLAGS = -iquote $(top_builddir) -iquote $(top_srcdir) -iquote $(top_srcdir)/cwds

SUBDIRS =

noinst_LTLIBRARIES = libevio.la

SOURCES = FileDescriptor.cxx \
	  FileDescriptor.h \
	  InputDevice.cxx \
	  InputDevice.h \
	  OutputDevice.cxx \
	  OutputDevice.h \
	  StreamBuf.cxx \
	  StreamBuf.h \
	  RefCountReleaser.cxx \
	  RefCountReleaser.h \
	  EventLoop.h \
	  EventLoop.cxx \
	  EventLoopThread.h \
	  EventLoopThread.cxx \
	  Protocol.cxx \
	  Protocol.h \
	  Socket.cxx \
	  Socket.h \
	  ListenSocket.h \
	  ListenSocket.cxx \
	  inet_support.cxx \
	  inet_support.h \
	  SocketAddress.cxx \
	  SocketAddress.h \
	  SocketAddressList.cxx \
	  SocketAddressList.h \
	  Interface.cxx \
	  Interface.h \
	  SocketNetmask.h \
	  File.cxx \
	  File.h \
	  PersistentInputFile.cxx \
	  PersistentInputFile.h \
	  INotify.cxx \
	  INotify.h \
	  Pipe.cxx \
	  Pipe.h

libevio_la_SOURCES = ${SOURCES}
libevio_la_CXXFLAGS = @LIBCWD_R_FLAGS@
libevio_la_LIBADD = ../threadpool/libthreadpool.la ../threadsafe/libthreadsafe.la ../utils/libutils_r.la @LIBCWD_R_LIBS@
