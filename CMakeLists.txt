cmake_minimum_required( VERSION 3.12...3.16 )

project( evio
         LANGUAGES C CXX
         DESCRIPTION "A cwm4 git submodule for embedding epoll based io event support" )

include( AICxxProject )

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
    PUBLIC
        AICxx::evio_protocol
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
