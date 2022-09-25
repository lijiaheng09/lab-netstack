set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tools)

link_libraries(lab-netstack pcap)

add_executable(console console.cpp)
add_executable(l2fwd l2fwd.cpp)
add_executable(eth_test eth_test.cpp)
