set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

add_library(lab-netstack
  netstack.cpp
  device.cpp
)

target_link_libraries(lab-netstack PRIVATE pcap)
