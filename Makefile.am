AM_CPPFLAGS = -iquote $(top_builddir) -iquote $(top_srcdir) -iquote $(top_srcdir)/cwds

SUBDIRS = protocol

noinst_LTLIBRARIES = libevio.la

SOURCES = FileDescriptor.cxx FileDescriptor.h \
	  InputDevice.cxx InputDevice.h \
	  OutputDevice.cxx OutputDevice.h \
	  StreamBuf.cxx StreamBuf.h \
	  RefCountReleaser.cxx RefCountReleaser.h \
	  EventLoop.cxx EventLoop.h \
	  EventLoopThread.cxx EventLoopThread.h \
	  Protocol.cxx Protocol.h \
	  Socket.cxx Socket.h \
	  TLSSocket.cxx TLSSocket.h \
	  ListenSocket.cxx ListenSocket.h \
	  inet_support.cxx inet_support.h \
	  SocketAddress.cxx SocketAddress.h \
	  SocketAddressList.cxx SocketAddressList.h \
	  Interface.cxx Interface.h \
	  File.cxx File.h \
	  PersistentInputFile.cxx PersistentInputFile.h \
	  INotify.cxx INotify.h \
	  Pipe.cxx Pipe.h \
	  SocketNetmask.h \
	  InputDecoder.cxx InputDecoder.h

libevio_la_SOURCES = ${SOURCES}
libevio_la_CXXFLAGS = @LIBCWD_R_FLAGS@
libevio_la_LIBADD = protocol/libprotocol.la ../threadpool/libthreadpool.la ../threadsafe/libthreadsafe.la ../utils/libutils_r.la @LIBCWD_R_LIBS@
