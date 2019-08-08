AM_CPPFLAGS = -iquote $(top_builddir) -iquote $(top_srcdir) -iquote $(top_srcdir)/cwds

SUBDIRS = protocol

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
libevio_la_LIBADD = protocol/libprotocol.la matrixssl/matrixssl/libssl_s.a matrixssl/core/libcore_s.a matrixssl/crypto/libcrypt_s.a ../threadpool/libthreadpool.la ../threadsafe/libthreadsafe.la ../utils/libutils_r.la @LIBCWD_R_LIBS@

matrixssl/matrixssl/libssl_s.a matrixssl/core/libcore_s.a matrixssl/crypto/libcrypt_s.a:
	@(cd $(abs_srcdir)/matrixssl; \
	  find . -type d \( -name doc -o -name 'test*' -o -name xcode -o -name thirdparty \) ! -name 'testsupp*' -false -prune -o \
	         \( -type d -exec mkdir -p $(abs_builddir)/matrixssl/{} \; \) -o \
		 \( -type f -exec ln -sf $(abs_srcdir)/matrixssl/{} $(abs_builddir)/matrixssl/{} \; \) \
	)
	$(MAKE) MATRIX_DEBUG=1 CFLAGS_EXTRA="-fPIC" -C matrixssl libs

clean-local:
	rm -rf $(abs_builddir)/matrixssl
