#include "common.h"
#include "commands.h"

#include <pcap/pcap.h>
#include <linux/if_arp.h>
#include <linux/if_packet.h>

class CmdAutoConfig : public Command {
public:
  CmdAutoConfig() : Command("auto-config") {}

  int main(int argc, char **argv) override {
    int rc = 0;

    bool route = (argc > 1 && strcmp(argv[1], "-r") == 0);
    int updateCycle = 30, expireCycle = 180, cleanCycle = 120;
    if (argc != 1 &&
        !(route && (argc == 2 ||
                    (argc == 5 && sscanf(argv[2], "%d", &updateCycle) == 1 &&
                     sscanf(argv[3], "%d", &expireCycle) == 1 &&
                     sscanf(argv[4], "%d", &cleanCycle) == 1)))) {
      fprintf(stderr,
              "Usage: %s [-r [update-cycle expire-cycle clean-cycle]]\n",
              argv[0]);
      return 1;
    }

    invoke([&]() {
      ns.autoConfig(!route);
      if (route) {

        if (ns.configRIP(updateCycle * 1s, expireCycle * 1s, cleanCycle * 1s) !=
            0) {
          fprintf(stderr, "Error setting up RIP routing.\n");
          rc = 1;
          return;
        }

        if (ns.enableForward() != 0) {
          fprintf(stderr, "Error setting up IP forwarding.\n");
          rc = 1;
          return;
        }
        printf("Enabled IP forwarding.\n");
      }

      rc = 0;
    });
    return rc;
  }
};
