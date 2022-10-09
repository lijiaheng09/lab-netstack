#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <vector>
#include <thread>

#include <readline/readline.h>
#include <readline/history.h>

#include <pcap/pcap.h>

#include <arpa/inet.h>

#include "NetStack.h"
#include "Ethernet.h"
#include "IPv4.h"
#include "LpmRouting.h"
#include "IPv4Forward.h"

NetStack netstack;
Ethernet ethernetLayer(netstack);
IPv4 ipv4Layer(ethernetLayer);
IPv4Forward ipv4Forward(ipv4Layer);
LpmRouting staticRouting;

std::vector<char *> devNames;

namespace commands {
int addDevice(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s <name>\n", argv[0]);
    return 1;
  }
  auto *d = ethernetLayer.addDeviceByName(argv[1]);
  if (!d) {
    return 1;
  }
  printf("device added: %s\n", d->name);
  printf("    ether " ETHERNET_ADDR_FMT_STRING "\n",
         ETHERNET_ADDR_FMT_ARGS(d->addr));
  return 0;
}

int findDevice(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s <name>\n", argv[0]);
    return 1;
  }
  auto *d = ethernetLayer.findDeviceByName(argv[1]);
  if (!d) {
    printf("device not found: %s\n", argv[1]);
    return 1;
  }
  printf("device found: %s\n", d->name);
  printf("    ether " ETHERNET_ADDR_FMT_STRING "\n",
         ETHERNET_ADDR_FMT_ARGS(d->addr));
  return 0;
}

int sendFrame(int argc, char **argv) {
  int id, etherType, padding = 0;
  Ethernet::Addr dstMAC;
  if (argc < 5 ||
      sscanf(argv[2], ETHERNET_ADDR_FMT_STRING,
             ETHERNET_ADDR_FMT_ARGS(&dstMAC)) != ETHERNET_ADDR_FMT_NUM ||
      sscanf(argv[3], "0x%x", &etherType) != 1 ||
      (argc == 6 && sscanf(argv[5], "%d", &padding) != 1) || argc > 6) {
    fprintf(stderr,
            "usage: %s <device> <dstMAC> 0x<etherType> <data> [padding]\n",
            argv[0]);
    return 1;
  }

  auto *d = ethernetLayer.findDeviceByName(argv[1]);
  if (!d) {
    fprintf(stderr, "device not found: %s\n", argv[1]);
    return 1;
  }

  int rLen = strlen(argv[4]);
  int len = rLen + padding;
  char *data = (char *)malloc(len);
  if (!data) {
    fprintf(stderr, "malloc error: %s\n", strerror(errno));
    return 1;
  }
  memcpy(data, argv[4], rLen);
  memset(data + rLen, 0, padding);

  int ret = d->sendFrame(data, len, dstMAC, etherType);
  free(data);

  if (ret != 0) {
    return 1;
  }
  return 0;
}

int startLoop(int argc, char **argv) {
  return netstack.loop();
}

class CaptureRecvCallback : public Ethernet::RecvCallback {
public:
  CaptureRecvCallback() : Ethernet::RecvCallback(-1) {}

  int handle(const void *buf, int len, Ethernet::Device *d) override {
    const auto &header = *(const Ethernet::Header *)buf;
    int etherType = ntohs(header.etherType);
    printf("Recv length %d from device %s\n", len, d->name);
    printf("    dst " ETHERNET_ADDR_FMT_STRING ", src " ETHERNET_ADDR_FMT_STRING
           ", ethtype 0x%04X\n",
           ETHERNET_ADDR_FMT_ARGS(header.dst),
           ETHERNET_ADDR_FMT_ARGS(header.src), etherType);
    return 0;
  }
} captureRecvCallback;

int enableEthernetCapture(int argc, char **argv) {
  ethernetLayer.addRecvCallback(&captureRecvCallback);
  return 0;
}

int addIPAddr(int argc, char **argv) {
  IPv4::Addr addr;
  if (argc != 3 || sscanf(argv[2], IPV4_ADDR_FMT_STRING,
                          IPV4_ADDR_FMT_ARGS(&addr)) != IPV4_ADDR_FMT_NUM) {
    fprintf(stderr, "usage: %s <device> <ip-addr>\n", argv[0]);
    return 1;
  }
  auto *d = ethernetLayer.findDeviceByName(argv[1]);
  if (!d) {
    fprintf(stderr, "device not found: %s\n", argv[1]);
    return 1;
  }
  ipv4Layer.addAddr(d, addr);
  return 0;
}

int setStaticRouting(int argc, char **argv) {
  ipv4Layer.setRouting(&staticRouting);
  return 0;
}

int setRoutingEntry(int argc, char **argv) {
  LpmRouting::Entry entry;
  if (argc != 5 ||
      sscanf(argv[1], IPV4_ADDR_FMT_STRING, IPV4_ADDR_FMT_ARGS(&entry.addr)) !=
          IPV4_ADDR_FMT_NUM ||
      sscanf(argv[2], IPV4_ADDR_FMT_STRING, IPV4_ADDR_FMT_ARGS(&entry.mask)) !=
          IPV4_ADDR_FMT_NUM ||
      sscanf(argv[4], ETHERNET_ADDR_FMT_STRING,
             ETHERNET_ADDR_FMT_ARGS(&entry.dstMAC)) != ETHERNET_ADDR_FMT_NUM) {
    fprintf(stderr, "usage: %s <ip> <mask> <device> <dstMAC>\n", argv[0]);
    return 1;
  }
  entry.device = ethernetLayer.findDeviceByName(argv[3]);
  if (!entry.device) {
    fprintf(stderr, "device not found: %s\n", argv[3]);
    return 1;
  }
  staticRouting.setEntry(entry);
  return 0;
}

int enableIPForward(int argc, char **argv) {
  return ipv4Forward.setup();
}

} // namespace commands

typedef int (*CommandHandler)(int argc, char **argv);

struct Command {
  const char *name;
  CommandHandler handler;
};

std::vector<Command> commandList = {
    {"add-device", commands::addDevice},
    {"find-device", commands::findDevice},
    {"start-loop", commands::startLoop},
    {"send-frame", commands::sendFrame},
    {"enable-ethernet-capture", commands::enableEthernetCapture},
    {"add-ip-addr", commands::addIPAddr},
    {"set-static-routing", commands::setStaticRouting},
    {"set-routing-entry", commands::setRoutingEntry},
    {"enable-ip-forward", commands::enableIPForward}};

std::vector<char *> splitLine(char *line) {
  std::vector<char *> args;
  char *p = line;
  args.push_back(p);
  while ((p = strchr(p, ' '))) {
    *p++ = '\0';
    while (*p && isspace(*p))
      p++;
    if (*p)
      args.push_back(p);
  }
  return args;
}

char *completionEntryDevs(const char *text, int state) {
  static std::vector<char *>::iterator cur;
  static int textLen;
  if (state == 0) {
    cur = devNames.begin();
    textLen = strlen(text);
  }

  while (cur != devNames.end()) {
    auto c = cur++;
    if (strncmp(*c, text, textLen) == 0)
      return strdup(*c);
  }
  return nullptr;
}

char *completionEntryCmds(const char *text, int state) {
  static std::vector<Command>::iterator cur;
  static int textLen;
  if (state == 0) {
    cur = commandList.begin();
    textLen = strlen(text);
  }

  while (cur != commandList.end()) {
    auto c = cur++;
    if (strncmp(c->name, text, textLen) == 0)
      return strdup(c->name);
  }
  return nullptr;
}

char **complete(const char *text, int start, int end) {
  char **matches = nullptr;
  if (start == 0)
    matches = rl_completion_matches(text, completionEntryCmds);
  else
    matches = rl_completion_matches(text, completionEntryDevs);
  return matches;
}

int main(int argc, char **argv) {
  if (netstack.setup() != 0 || ethernetLayer.setup() != 0 ||
      ipv4Layer.setup() != 0) {
    return 1;
  }

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *alldevs;
  if (pcap_findalldevs(&alldevs, errbuf) != 0) {
    fprintf(stderr, "pcap_findalldevs error: %s\n", errbuf);
    return 1;
  }
  for (auto *d = alldevs; d; d = d->next)
    devNames.push_back(strdup(d->name));

  rl_attempted_completion_function = complete;

  while (true) {
    char *line = readline("> ");
    if (!line) {
      puts("exit");
      return 0;
    }
    add_history(line);

    auto args = splitLine(line);
    int iargc = (int)args.size();
    char **iargv = args.data();

    CommandHandler handler = nullptr;
    for (auto &&c : commandList)
      if (strcmp(c.name, iargv[0]) == 0)
        handler = c.handler;
    if (handler == nullptr)
      fprintf(stderr, "command not found\n");
    else
      handler(iargc, iargv);
  }
  return 0;
}
