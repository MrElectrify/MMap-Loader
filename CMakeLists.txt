cmake_minimum_required(VERSION 3.10)

project(mmap-loader
	VERSION 1.0
	DESCRIPTION "Manual map loader"
	LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
   add_compile_options (-fdiagnostics-color=always)
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
   add_compile_options (-fcolor-diagnostics)
endif ()

add_subdirectory(extern/Blackbone/src)
add_subdirectory(src)