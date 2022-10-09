set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tools)

add_subdirectory(cli)

find_package(Threads)
add_executable(eth_test eth_test.cpp)
target_link_libraries(eth_test
  lab-netstack
  ${CMAKE_THREAD_LIBS_INIT}
)
