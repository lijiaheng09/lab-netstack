#ifndef TOOLS_COMMANDS_H
#define TOOLS_COMMANDS_H

#include <cstdio>

#include <vector>

class Command {
public:
  char *const name;

  Command(const char *name_);
  Command(const Command &) = delete;
  ~Command();

  virtual int main(int argc, char **argv) = 0;
};

extern std::vector<Command *> allCommands;

#endif
