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

    IP::DevAddr entry {
      device: d,
      addr: addr,
      mask: mask
    };

    invoke([&]() { ip.addAddr(entry); });
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
    invoke([&]() { rc = routing.setEntry(entry); });
    if (rc != 0) {
      fprintf(stderr, "Error setting routing entry.");
      return 1;
    }
    return 0;
  }
};
