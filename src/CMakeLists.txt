project(MMapLoader CXX)

file(GLOB_RECURSE sourceFiles ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp)

add_library(MMapLoader ${sourceFiles})

target_include_directories(MMapLoader
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../include)