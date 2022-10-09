set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -DNETSTACK_DEBUG")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DNETSTACK_DEBUG")

add_library(lab-netstack
  utils.cpp
  LoopDispatcher.cpp
  
  NetBase.cpp
  Ethernet.cpp
  IP.cpp
  ICMP.cpp
  IPForward.cpp
  LpmRouting.cpp
  UDP.cpp
)

target_link_libraries(lab-netstack PRIVATE pcap)
