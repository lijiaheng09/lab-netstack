set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tools)

find_package(Threads)

link_libraries(lab-netstack pcap)

add_executable(console console.cpp)
add_executable(eth_test eth_test.cpp)

target_link_libraries(console readline)
target_link_libraries(eth_test ${CMAKE_THREAD_LIBS_INIT})
