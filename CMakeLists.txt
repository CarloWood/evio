cmake_minimum_required(VERSION 3.12...3.16)

project(evio
  DESCRIPTION "A cwm4 git submodule for embedding epoll based io event support"
  LANGUAGES C CXX
)

include(AICxxProject)

#==============================================================================
# OPTIONS

# Option 'EnableDebugBuffers' is available when OptionEnableLibcwd is ON (otherwise OFF).
# Turns on debugging for the buffers library itself. Only interesting when working on the source of this library.
cw_option(EnableDebugBuffers
    "Enable debugging of the dynamic blocks stream buffer." OFF
    "OptionEnableLibcwd" OFF
)

if (OptionEnableDebugBuffers)
  set(DEBUGDBSTREAMBUF 1)
endif ()

#==============================================================================
# SUBDIRECTORIES

add_subdirectory(protocol)

#==============================================================================
# BUILD PROJECT
#

# This project is an OBJECT-library, used by other git submodules and the main project.
add_library(evio_ObjLib OBJECT)

# Set SOURCE_DIR to the current directory.
set_property(
  TARGET evio_ObjLib
  PROPERTY SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}"
)

# The list of source files.
target_sources(evio_ObjLib
  PRIVATE
    "EventLoop.cxx"
    "EventLoopThread.cxx"
    "File.cxx"
    "FileDescriptor.cxx"
    "inet_support.cxx"
    "INotify.cxx"
    "InputDevice.cxx"
    "Interface.cxx"
    "ListenSocket.cxx"
    "OutputDevice.cxx"
    "PersistentInputFile.cxx"
    "Pipe.cxx"
    "Protocol.cxx"
    "RefCountReleaser.cxx"
    "Sink.cxx"
    "SocketAddress.cxx"
    "SocketAddressList.cxx"
    "Socket.cxx"
    "Source.cxx"
    "StreamBuf.cxx"
    "TLSSocket.cxx"

    "AcceptedSocket.h"
    "EventLoop.h"
    "EventLoopThread.h"
    "FileDescriptor.h"
    "File.h"
    "inet_support.h"
    "INotify.h"
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
get_target_property(CWDS_INTERFACE_INCLUDE_DIRECTORIES AICxx::cwds INTERFACE_INCLUDE_DIRECTORIES)
target_include_directories(evio_ObjLib
  PUBLIC
    "${CWDS_INTERFACE_INCLUDE_DIRECTORIES}" # For sys.h and debug.h.
)

# Require support for C++17.
target_compile_features(evio_ObjLib
  PUBLIC cxx_std_17
)

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
  if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS 8)
    unset(CMAKE_C_COMPILER CACHE)
    unset(CMAKE_C_COMPILER_AR CACHE)
    unset(CMAKE_C_COMPILER_RANLIB CACHE)
    unset(CMAKE_CXX_COMPILER CACHE)
    unset(CMAKE_CXX_COMPILER_AR CACHE)
    unset(CMAKE_CXX_COMPILER_ARG1 CACHE)
    unset(CMAKE_CXX_COMPILER_RANLIB CACHE)
    unset(CMAKE_PLATFORM_INFO_INITIALIZED CACHE)
    # The above might not be sufficient.
    message(WARNING "Manually remove \"${CMAKE_BINARY_DIR}/CMakeCache.txt\"!")
    # Although cmake thinks that g++ 7.x is sufficient for C++17, it doesn't have std::from_chars.
    message(FATAL_ERROR "At least g++ 8.x is required (9.0+ recommended), or clang++ 6.0+.")
  endif ()
endif ()

# Set link dependencies.
target_link_libraries(evio_ObjLib
  PUBLIC
    AICxx::evio_protocol
    AICxx::threadpool
)

# Create an ALIAS target.
add_library(AICxx::evio ALIAS evio_ObjLib)

# Prepend this object library to the list.
set(AICXX_OBJECTS_LIST AICxx::evio ${AICXX_OBJECTS_LIST} CACHE INTERNAL "List of OBJECT libaries that this project uses.")
