#include "netstack.h"
#include "commands.h"

class CmdIPAddrAdd : public Command {
public:
  CmdIPAddrAdd() : Command("ip-addr-add") {}

  int main(int argc, char **argv) override {
    IP::Addr addr, mask;
    if (argc != 4 ||
        sscanf(argv[1], IP_ADDR_FMT_STRING, IP_ADDR_FMT_ARGS(&addr)) !=
            IP_ADDR_FMT_NUM ||
        sscanf(argv[2], IP_ADDR_FMT_STRING, IP_ADDR_FMT_ARGS(&mask)) !=
            IP_ADDR_FMT_NUM) {
      fprintf(stderr, "Usage: %s <ip> <mask> <device>\n", argv[0]);
      return 1;
    }

    auto *d = findDeviceByName(argv[3]);
    if (!d)
      return 1;

    IP::DevAddr entry{device : d, addr : addr, mask : mask};

    INVOKE({ ip.addAddr(entry); })
    return 0;
  }
};

class CmdRouteAdd : public Command {
public:
  CmdRouteAdd() : Command("route-add") {}

  int main(int argc, char **argv) override {
    LpmRouting::Entry entry;
    if (argc != 5 ||
        sscanf(argv[1], IP_ADDR_FMT_STRING, IP_ADDR_FMT_ARGS(&entry.addr)) !=
            IP_ADDR_FMT_NUM ||
        sscanf(argv[2], IP_ADDR_FMT_STRING, IP_ADDR_FMT_ARGS(&entry.mask)) !=
            IP_ADDR_FMT_NUM ||
        sscanf(argv[4], ETHERNET_ADDR_FMT_STRING,
               ETHERNET_ADDR_FMT_ARGS(&entry.dstMAC)) !=
            ETHERNET_ADDR_FMT_NUM) {
      fprintf(stderr, "usage: %s <ip> <mask> <device> <dstMAC>\n", argv[0]);
      return 1;
    }

    entry.device = findDeviceByName(argv[3]);
    if (!entry.device)
      return 1;

    int rc;
    INVOKE({ rc = staticRouting.setEntry(entry); })
    if (rc != 0) {
      fprintf(stderr, "Error setting routing entry.");
      return 1;
    }
    return 0;
  }
};

class CmdRouteRip : public Command {
public:
  CmdRouteRip() : Command("route-rip") {}

  int main(int argc, char **argv) override {
    int rc;
    INVOKE({ rc = ripRouting.setup(); })
    if (rc != 0) {
      fprintf(stderr, "Error setting up RIP routing.\n");
      return 1;
    }
    INVOKE({ ip.setRouting(&ripRouting); })
    return 0;
  }
};

class CmdRouteRipInfo : public Command {
public:
  CmdRouteRipInfo() : Command("route-rip-info") {}

  int main(int argc, char **argv) override {
    IP::Routing::HopInfo res;
    INVOKE({
      const auto &table = ripRouting.getTable();
      printf("IP | Device | Dest MAC | Metric | Exipre\n");
      time_t curTime = time(nullptr);
      for (auto &&e : table) {
        printf(IP_ADDR_FMT_STRING " | %s | " ETHERNET_ADDR_FMT_STRING
                                  " | %d | %+ld\n",
               IP_ADDR_FMT_ARGS(e.first), e.second.device->name,
               ETHERNET_ADDR_FMT_ARGS(e.second.dstMAC), e.second.metric,
               e.second.expireTime - curTime);
      }
    })
    return 0;
  }
};
