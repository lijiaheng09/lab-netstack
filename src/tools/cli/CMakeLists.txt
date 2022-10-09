include_directories(include)

add_executable(cli
  cli.cpp
  netstack.cpp
  common.cpp
  commands.cpp
)

find_package(Threads)
target_link_libraries(cli
  lab-netstack
  readline
  ${CMAKE_THREAD_LIBS_INIT}
)
