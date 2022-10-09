#include "netstack.h"
#include "commands.h"

class CmdAddDevice : public Command {
public:
  CmdAddDevice() : Command("add-device") {}

  int main(int argc, char **argv) override {
    if (argc != 2) {
      fprintf(stderr, "Usage: %s <name>\n", argv[0]);
      return 1;
    }

    auto *d = ethernet.addDeviceByName(argv[1]);
    if (!d) {
      return 1;
    }
    printf("Device added: %s\n", d->name);
    printf("    ether " ETHERNET_ADDR_FMT_STRING "\n",
           ETHERNET_ADDR_FMT_ARGS(d->addr));

    return 0;
  }
};

class CmdFindDevice : public Command {
public:
  CmdFindDevice() : Command("find-device") {}

  int main(int argc, char **argv) override {
    if (argc != 2) {
      fprintf(stderr, "Usage: %s <name>\n", argv[0]);
      return 1;
    }

    auto *d = ethernet.findDeviceByName(argv[1]);
    if (!d) {
      printf("Device not found: %s\n", argv[1]);
      return 1;
    }
    printf("Device found: %s\n", d->name);
    printf("    ether " ETHERNET_ADDR_FMT_STRING "\n",
           ETHERNET_ADDR_FMT_ARGS(d->addr));

    return 0;
  }
};
