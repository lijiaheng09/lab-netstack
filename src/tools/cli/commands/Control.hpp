#include "common.h"
#include "commands.h"

#include <thread>

class CmdStartLoop : public Command {
public:
  CmdStartLoop() : Command("start-loop") {}

  int main(int argc, char **argv) override {
    ns.start();
    return 0;
  }
};

class CmdSleep : public Command {
public:
  CmdSleep() : Command("sleep") {}

  int main(int argc, char **argv) override {
    using namespace std::chrono_literals;

    int t;
    if (argc != 2 || sscanf(argv[1], "%d", &t) != 1) {
      fprintf(stderr, "Usage: %s <time>\n", argv[0]);
      return 1;
    }
    std::this_thread::sleep_for(t * 1s);
    return 0;
  }
};

