AM_CPPFLAGS = -iquote $(top_builddir) -iquote $(top_srcdir) -iquote $(top_srcdir)/cwds

SUBDIRS =

noinst_LTLIBRARIES = libprotocol.la

SOURCES = TLS.cxx \
	  TLS.h

libprotocol_la_SOURCES = ${SOURCES}
libprotocol_la_CXXFLAGS = @WOLFSSL_CFLAGS@ @LIBCWD_R_FLAGS@
libprotocol_la_LIBADD = @WOLFSSL_LIBS@ @LIBCWD_R_LIBS@
