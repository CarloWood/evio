cmake_minimum_required( VERSION 3.12...3.16 )

project( evio
         LANGUAGES C CXX
         DESCRIPTION "A cwm4 git submodule for embedding epoll based io event support" )

include( AICxxProject )
include( ExternalProject )
include( ProcessorCount )

ProcessorCount( N )
if ( NOT N EQUAL 0 )
  set( MAKE_OPTIONS "-j${N}" )
else ()
  set( MAKE_OPTIONS "" )
endif ()

ExternalProject_Add( MatrixSSL
  SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/matrixssl
  PREFIX ${CMAKE_CURRENT_BINARY_DIR}/matrixssl
  CONFIGURE_COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/configure_matrixssl.sh" "${CMAKE_CURRENT_SOURCE_DIR}" "${CMAKE_CURRENT_BINARY_DIR}"
  BUILD_COMMAND "${CMAKE_MAKE_PROGRAM}" ${MAKE_OPTIONS}
  BUILD_BYPRODUCTS "${CMAKE_CURRENT_BINARY_DIR}/matrixssl/.libs/libssl_s.a"
                   "${CMAKE_CURRENT_BINARY_DIR}/crypto/.libs/libcrypt_s.a"
                   "${CMAKE_CURRENT_BINARY_DIR}/core/.libs/libcore_s.a"
  STEP_TARGETS build
  INSTALL_COMMAND ""
  EXCLUDE_FROM_ALL TRUE
)

ExternalProject_Get_property( MatrixSSL SOURCE_DIR )
ExternalProject_Get_property( MatrixSSL BINARY_DIR )

ExternalProject_Add_StepDependencies( MatrixSSL configure
    ${CMAKE_CURRENT_SOURCE_DIR}/configure_matrixssl.sh
    ${SOURCE_DIR}/configure.ac
    ${SOURCE_DIR}/makefile.am
    ${SOURCE_DIR}/apps/common/makefile.am
    ${SOURCE_DIR}/apps/dtls/makefile.am
    ${SOURCE_DIR}/apps/ssl/makefile.am
    ${SOURCE_DIR}/apps/makefile.am
    ${SOURCE_DIR}/core/makefile.am
    ${SOURCE_DIR}/crypto/makefile.am
    ${SOURCE_DIR}/matrixssl/makefile.am
)

add_library( evio_matrixssl_IfLib INTERFACE IMPORTED )
add_dependencies( evio_matrixssl_IfLib MatrixSSL-build )

set_property( TARGET evio_matrixssl_IfLib PROPERTY INTERFACE_POSITION_INDEPENDENT_CODE ON )
# According to https://www.gnu.org/software/libtool/manual/libtool.html#Creating-object-files libraries in .libs are always PIC.
target_link_libraries( evio_matrixssl_IfLib
    INTERFACE
        "${BINARY_DIR}/matrixssl/.libs/libssl_s.a"
        "${BINARY_DIR}/crypto/.libs/libcrypt_s.a"
        "${BINARY_DIR}/core/.libs/libcore_s.a"
)
target_include_directories( evio_matrixssl_IfLib
    INTERFACE
        "${BINARY_DIR}"
        "${SOURCE_DIR}"
        "${SOURCE_DIR}/core/include"
        "${SOURCE_DIR}/core/osdep/include"
)
target_compile_options( evio_matrixssl_IfLib
    INTERFACE
        "-maes"
)
target_compile_definitions( evio_matrixssl_IfLib
    INTERFACE
        "MATRIX_CONFIGURATION_INCDIR_FIRST"
)

add_subdirectory( protocol )

#==============================================================================
# DEPENDENCIES
#

# This project uses boost::intrusive_ptr.
find_package( Boost REQUIRED )

#==============================================================================
# OPTIONS

# Option 'EnableDebugBuffers' is available when OptionEnableLibcwd is ON (otherwise OFF).
# Turns on debugging for the buffers library itself. Only interesting when working on the source of this library.
cw_option( EnableDebugBuffers
        "Enable debugging of the dynamic blocks stream buffer." OFF
        "OptionEnableLibcwd" OFF )

if ( OptionEnableDebugBuffers )
  set( DEBUGDBSTREAMBUF 1 )
endif ()

#==============================================================================
# BUILD PROJECT
#

# This project is an OBJECT-library, used by other git submodules and the main project.
add_library( evio_ObjLib OBJECT )

# Set SOURCE_DIR to the current directory.
set_property(
    TARGET     evio_ObjLib
    PROPERTY   SOURCE_DIR       "${CMAKE_CURRENT_SOURCE_DIR}"
)

# The list of source files.
target_sources( evio_ObjLib
    PRIVATE
        "EventLoop.cxx"
        "EventLoopThread.cxx"
        "File.cxx"
        "FileDescriptor.cxx"
        "inet_support.cxx"
        "INotify.cxx"
        "InputDecoder.cxx"
        "InputDevice.cxx"
        "Interface.cxx"
        "ListenSocket.cxx"
        "OutputDevice.cxx"
        "PersistentInputFile.cxx"
        "Pipe.cxx"
        "Protocol.cxx"
        "RefCountReleaser.cxx"
        "SocketAddress.cxx"
        "SocketAddressList.cxx"
        "Socket.cxx"
        "StreamBuf.cxx"
        "TLSSocket.cxx"

        "AcceptedSocket.h"
        "EventLoop.h"
        "EventLoopThread.h"
        "FileDescriptor.h"
        "File.h"
        "inet_support.h"
        "INotify.h"
        "InputDecoder.h"
        "InputDevice.h"
        "Interface.h"
        "ListenSocket.h"
        "OutputDevice.h"
        "OutputStream.h"
        "PersistentInputFile.h"
        "Pipe.h"
        "Protocol.h"
        "RefCountReleaser.h"
        "Sink.h"
        "SocketAddress.h"
        "SocketAddressList.h"
        "Socket.h"
        "SocketNetmask.h"
        "Source.h"
        "StreamBuf.h"
        "StreamBuf-threads.h"
        "TLSSocket.h"
)

# Required include search-paths.
get_target_property( CWDS_INTERFACE_INCLUDE_DIRECTORIES AICxx::cwds INTERFACE_INCLUDE_DIRECTORIES )
target_include_directories( evio_ObjLib
    PUBLIC
        "${CWDS_INTERFACE_INCLUDE_DIRECTORIES}" # For sys.h and debug.h.
)

# Require support for C++17.
target_compile_features( evio_ObjLib
    PUBLIC cxx_std_17
)

# Set link dependencies.
target_link_libraries( evio_ObjLib
    PRIVATE
        AICxx::utils
    INTERFACE
        evio_matrixssl_IfLib
    PUBLIC
        Boost::boost
        Threads::Threads
)

if ( OptionEnableLibcwd )
  target_link_libraries( evio_ObjLib
      PUBLIC
          PkgConfig::Libcwd_r
)
endif ()

# Create an ALIAS target.
add_library( AICxx::evio ALIAS evio_ObjLib )

# Prepend this object library to the list.
set( AICXX_OBJECTS_LIST AICxx::evio ${AICXX_OBJECTS_LIST} CACHE INTERNAL "List of OBJECT libaries that this project uses." )
