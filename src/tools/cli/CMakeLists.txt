include_directories(include)

add_executable(cli
  cli.cpp
  commands.cpp
  netstack.cpp
)
target_link_libraries(cli
  lab-netstack
  readline
)
