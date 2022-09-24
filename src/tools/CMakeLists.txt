set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tools)

add_executable(console console.cpp)
target_link_libraries(console lab-netstack pcap)
