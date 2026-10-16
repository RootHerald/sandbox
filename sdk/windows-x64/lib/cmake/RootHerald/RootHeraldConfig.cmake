include("${CMAKE_CURRENT_LIST_DIR}/RootHeraldTargets.cmake")

# Only Debug ships RootHeraldd.lib (/MDd); every other configuration takes Release.
set_target_properties(RootHerald::sdk PROPERTIES
    MAP_IMPORTED_CONFIG_RELWITHDEBINFO Release
    MAP_IMPORTED_CONFIG_MINSIZEREL Release
)

if(MSVC AND CMAKE_MSVC_RUNTIME_LIBRARY MATCHES "MultiThreaded(Debug|\\$<\\$<CONFIG:Debug>:Debug>)?([,>;]|$)")
    message(FATAL_ERROR "RootHerald.lib is built against the dynamic CRT (/MD, /MDd); set CMAKE_MSVC_RUNTIME_LIBRARY to a DLL runtime.")
endif()
