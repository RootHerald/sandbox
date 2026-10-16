cmake_minimum_required(VERSION 3.21)
project(sandbox_client C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

find_package(RootHerald 0.7 REQUIRED CONFIG)

if(WIN32)
    add_executable(sandbox-client main.c platform_windows.c)
    target_link_libraries(sandbox-client PRIVATE RootHerald::sdk winhttp shell32)
else()
    find_package(CURL REQUIRED)
    add_executable(sandbox-client main.c platform_linux.c)
    target_link_libraries(sandbox-client PRIVATE RootHerald::sdk CURL::libcurl)
endif()

if(MSVC)
    target_compile_options(sandbox-client PRIVATE /W4 /utf-8)
else()
    target_compile_options(sandbox-client PRIVATE -Wall -Wextra)
endif()

# One state directory for every way the program starts: the IDE, the command
# line, and the elevated relaunch, which starts in a different working directory.
target_compile_definitions(sandbox-client PRIVATE SANDBOX_STATE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/state")
