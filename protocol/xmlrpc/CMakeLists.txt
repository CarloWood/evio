cmake_minimum_required(VERSION 3.15...3.30)

project(xmlrpc
  DESCRIPTION "evio xmlrpc objects."
  LANGUAGES CXX
)

include(AICxxProject)

find_package(magic_enum REQUIRED)

#==============================================================================
# BUILD PROJECT
#

# This project is an OBJECT-library, used by other git submodules and the main project.
add_library(evio_protocol_xmlrpc_ObjLib OBJECT)

# The list of source files.
target_sources(evio_protocol_xmlrpc_ObjLib
  PRIVATE
    "ElementDecoder.cxx"
    "ElementDecoder.h"
    "IgnoreElement.cxx"
    "IgnoreElement.h"
    "initialize.h"
    "create_member_decoder.h"
    "ArrayOfStructDecoder.h"
    "ArrayOfMemberDecoder.h"
    "DecoderBase.h"
    "macros.h"
    "MemberDecoder.h"
    "RequestParam.cxx"
    "RequestParam.h"
    "StructDecoder.h"
    "SingleStructResponse.h"
    "StructDictionary.h"
    "Decoder.cxx"
    "Decoder.h"
    "Encoder.cxx"
    "Encoder.h"
)

# Required include search-paths.
get_target_property(CWDS_INTERFACE_INCLUDE_DIRECTORIES AICxx::cwds INTERFACE_INCLUDE_DIRECTORIES)
target_include_directories(evio_protocol_xmlrpc_ObjLib
  PUBLIC
    "${CWDS_INTERFACE_INCLUDE_DIRECTORIES}" # For sys.h and debug.h.
)

# Require support for C++17.
target_compile_features(evio_protocol_xmlrpc_ObjLib
  PUBLIC cxx_std_17
)

# Set link dependencies.
target_link_libraries(evio_protocol_xmlrpc_ObjLib
  PRIVATE
    AICxx::utils
    magic_enum::magic_enum
)

# Create an ALIAS target.
add_library(AICxx::evio_protocol_xmlrpc ALIAS evio_protocol_xmlrpc_ObjLib)
