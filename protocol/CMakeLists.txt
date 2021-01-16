message(STATUS "----------------------------------------------------\n** Configuring subdirectory evio/protocol:")

find_package(wolfssl REQUIRED)

add_library(evio_protocol_ObjLib OBJECT)

#==============================================================================
# BUILD PROJECT
#

# The list of source files.
target_sources(evio_protocol_ObjLib
  PRIVATE
    TLS.cxx
    TLS.h
    http.cxx
    http.h
    MessageLengthInterface.cxx
    MessageLengthInterface.h
    Decoder.cxx
    Decoder.h
    DecoderStream.h
    EOFDecoder.cxx
    EOFDecoder.h
)

# Required include search-paths.
get_target_property(CWDS_INTERFACE_INCLUDE_DIRECTORIES AICxx::cwds INTERFACE_INCLUDE_DIRECTORIES)
target_include_directories(evio_protocol_ObjLib
  PUBLIC
    "${CWDS_INTERFACE_INCLUDE_DIRECTORIES}" # For sys.h and debug.h.
)

# Require support for C++17.
target_compile_features(evio_protocol_ObjLib
  PUBLIC cxx_std_17
)

target_link_libraries(evio_protocol_ObjLib
  PUBLIC
    wolfssl::wolfssl
    AICxx::utils
)

# Create an ALIAS target.
add_library(AICxx::evio_protocol ALIAS evio_protocol_ObjLib)

# Prepend this object library to list.
set(AICXX_OBJECTS_LIST AICxx::evio_protocol ${AICXX_OBJECTS_LIST} CACHE INTERNAL "List of OBJECT libaries that this project uses.")
