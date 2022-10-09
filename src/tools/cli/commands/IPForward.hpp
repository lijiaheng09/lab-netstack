#include "netstack.h"
#include "commands.h"

class CmdIPForward : public Command {
public:
  CmdIPForward() : Command("ip-forward") {}

  int main(int argc, char **argv) override {
    int rc = ipv4Forward.setup();
    if (rc != 0)
      fprintf(stderr, "Error setting up IPv4 forwarding\n");
    return rc;
  }
};
