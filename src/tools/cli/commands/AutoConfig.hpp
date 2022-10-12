#include "netstack.h"
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
                    (argc == 5 && sscanf(argv[2], "%d", &updateCycle) != 1 &&
                     sscanf(argv[3], "%d", &expireCycle) != 1 &&
                     sscanf(argv[4], "%d", &cleanCycle) != 1)))) {
      fprintf(stderr,
              "Usage: %s [-r [update-cycle expire-cycle clean-cycle]]\n",
              argv[0]);
      return 1;
    }

    invoke([&]() {
      char errbuf[PCAP_ERRBUF_SIZE];
      pcap_if_t *allDevs;
      if (pcap_findalldevs(&allDevs, errbuf) != 0) {
        fprintf(stderr, "pcap_findalldevs error: %s\n", errbuf);
        rc = 1;
        return;
      }
      for (auto *p = allDevs; p; p = p->next) {
        bool isEthernet = false;
        for (auto *a = p->addresses; a; a = a->next)
          if (a->addr && a->addr->sa_family == AF_PACKET) {
            sockaddr_ll *s = (sockaddr_ll *)a->addr;
            if (s->sll_hatype == ARPHRD_ETHER) {
              isEthernet = true;
              break;
            }
          }
        if (!isEthernet)
          continue;
        if (auto *d = ethernet.addDeviceByName(p->name)) {
          printf("Device added: %s\n", d->name);
          printf("    ether " ETHERNET_ADDR_FMT_STRING "\n",
                 ETHERNET_ADDR_FMT_ARGS(d->addr));
          for (auto *a = p->addresses; a; a = a->next)
            if (a->addr && a->addr->sa_family == AF_INET) {
              IP::Addr addr, mask;
              memcpy(&addr, &((sockaddr_in *)a->addr)->sin_addr,
                     sizeof(IP::Addr));
              memcpy(&mask, &((sockaddr_in *)a->netmask)->sin_addr,
                     sizeof(IP::Addr));
              ip.addAddr({device : d, addr : addr, mask : mask});
              printf("    inet " IP_ADDR_FMT_STRING
                     " netmask " IP_ADDR_FMT_STRING "\n",
                     IP_ADDR_FMT_ARGS(addr), IP_ADDR_FMT_ARGS(mask));
            }
        }
      }
      pcap_freealldevs(allDevs);

      if (route) {
        ripRouting.updateCycle = updateCycle;
        ripRouting.expireCycle = expireCycle;
        ripRouting.cleanCycle = cleanCycle;
        if (ripRouting.setup() != 0) {
          fprintf(stderr, "Error setting up RIP routing.\n");
          rc = 1;
          return;
        }
        ip.setRouting(&ripRouting);
        printf("Set to RIP routing.\n");

        if (ipForward.setup() != 0) {
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
