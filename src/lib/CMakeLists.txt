set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -DNETSTACK_DEBUG")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DNETSTACK_DEBUG")

add_library(lab-netstack
  NetStack.cpp
  Ethernet.cpp
)

target_link_libraries(lab-netstack PRIVATE pcap)
