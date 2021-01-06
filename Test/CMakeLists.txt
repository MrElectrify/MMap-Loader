project(Test CXX)

file(GLOB_RECURSE sourceFiles "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp")

add_executable(Test ${sourceFiles})

target_link_libraries(Test
	PUBLIC MMapLoader)