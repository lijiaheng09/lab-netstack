#include "netstack.h"
#include "commands.h"

class CmdStartLoop : public Command {
public:
  CmdStartLoop() : Command("start-loop") {}

  int main(int argc, char **argv) override {
    return startLoop();
  }
};
