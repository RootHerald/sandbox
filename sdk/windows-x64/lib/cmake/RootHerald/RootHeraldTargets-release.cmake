#----------------------------------------------------------------
# Generated CMake target import file for configuration "Release".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "RootHerald::sdk" for configuration "Release"
set_property(TARGET RootHerald::sdk APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(RootHerald::sdk PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "C"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/RootHerald.lib"
  )

list(APPEND _cmake_import_check_targets RootHerald::sdk )
list(APPEND _cmake_import_check_files_for_RootHerald::sdk "${_IMPORT_PREFIX}/lib/RootHerald.lib" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
