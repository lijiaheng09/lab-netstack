set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

find_package(Threads)

add_library(lab-netstack
  netstack.cpp
  device.cpp
  packetio.cpp
)

target_link_libraries(lab-netstack PRIVATE pcap ${CMAKE_THREAD_LIBS_INIT})
