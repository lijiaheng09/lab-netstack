#include <cstring>
#include <cstdlib>
#include <cerrno>

#include <arpa/inet.h>

#include "netstack.h"
#include "commands.h"

class CmdSendFrame : public Command {
public:
  CmdSendFrame() : Command("send-frame") {}

  int main(int argc, char **argv) override {
    int etherType, padding = 0;
    Ethernet::Addr dstMAC;

    if (argc < 5 ||
        sscanf(argv[2], ETHERNET_ADDR_FMT_STRING,
               ETHERNET_ADDR_FMT_ARGS(&dstMAC)) != ETHERNET_ADDR_FMT_NUM ||
        sscanf(argv[3], "0x%x", &etherType) != 1 ||
        (argc == 6 && sscanf(argv[5], "%d", &padding) != 1) || argc > 6) {
      fprintf(stderr,
              "Usage: %s <device> <dstMAC> 0x<etherType> <data> [padding]\n",
              argv[0]);
      return 1;
    }

    auto *d = findDeviceByName(argv[1]);
    if (!d)
      return 1;

    int rLen = strlen(argv[4]);
    int len = rLen + padding;
    char *data = (char *)malloc(len);
    if (!data) {
      fprintf(stderr, "malloc error: %s\n", strerror(errno));
      return 1;
    }
    memcpy(data, argv[4], rLen);
    memset(data + rLen, 0, padding);

    int rc;
    INVOKE({ rc = ethernet.send(data, len, dstMAC, etherType, d); })

    free(data);
    if (rc != 0) {
      fprintf(stderr, "Error sending frame.\n");
      return 1;
    }
    return 0;
  }
};

class CmdCaptureFrames : public Command {
  class Handler : public Ethernet::RecvCallback {
  public:
    Handler() : Ethernet::RecvCallback(-1) {}

    int handle(const void *data, int dataLen, const Info &info) override {
      int etherType = ntohs(info.linkHeader->etherType);
      printf("Data length %d from device %s\n", dataLen, info.linkDevice->name);
      printf("    dst " ETHERNET_ADDR_FMT_STRING
             ", src " ETHERNET_ADDR_FMT_STRING ", ethtype 0x%04X\n",
             ETHERNET_ADDR_FMT_ARGS(info.linkHeader->dst),
             ETHERNET_ADDR_FMT_ARGS(info.linkHeader->src), etherType);

      return 0;
    }
  } handler;

public:
  CmdCaptureFrames() : Command("capture-frames") {}

  int main(int argc, char **argv) override {
    INVOKE({ ethernet.addRecvCallback(&handler); })
    return 0;
  }
};
