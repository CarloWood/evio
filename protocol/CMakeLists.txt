add_library( evio_protocol_ObjLib OBJECT )

# The list of source files.
target_sources( evio_protocol_ObjLib
    PRIVATE
        "TLS.cxx"

        "TLS.h"
)

# Required include search-paths.
get_target_property( CWDS_INTERFACE_INCLUDE_DIRECTORIES AICxx::cwds INTERFACE_INCLUDE_DIRECTORIES )
target_include_directories( evio_protocol_ObjLib
    PUBLIC
        "${CWDS_INTERFACE_INCLUDE_DIRECTORIES}" # For sys.h and debug.h.
)

# Require support for C++17.
target_compile_features( evio_protocol_ObjLib
    PUBLIC cxx_std_17
)

target_link_libraries( evio_protocol_ObjLib
    PUBLIC
        evio_matrixssl_IfLib
        AICxx::utils
        Threads::Threads
)

if ( OptionEnableLibcwd )
  target_link_libraries( evio_protocol_ObjLib
      PUBLIC
          PkgConfig::Libcwd_r
)
endif ()

# Create an ALIAS target.
add_library( AICxx::evio_protocol ALIAS evio_protocol_ObjLib )

# Prepend this object library to list.
set( AICXX_OBJECTS_LIST AICxx::evio_protocol ${AICXX_OBJECTS_LIST} CACHE INTERNAL "List of OBJECT libaries that this project uses." )
