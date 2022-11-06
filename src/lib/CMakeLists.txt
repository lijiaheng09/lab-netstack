set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -DNETSTACK_DEBUG")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DNETSTACK_DEBUG")

add_library(lab-netstack
  utils.cpp
  TaskDispatcher.cpp
  Timer.cpp

  NetBase.cpp
  Ethernet.cpp
  IP.cpp
  ARP.cpp
  ICMP.cpp
  IPForward.cpp
  LpmRouting.cpp
  UDP.cpp
  RIP.cpp

  NetStackSimple.cpp
  NetStackFull.cpp
)

target_link_libraries(lab-netstack PRIVATE pcap)
