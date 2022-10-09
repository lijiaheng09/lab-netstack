#include "netstack.h"
#include "commands.h"

class CmdCapturePackets : public Command {
  class Handler : public IPv4::RecvCallback {
  public:
    Handler() : IPv4::RecvCallback(true, -1) {}

    int handle(const void *buf, int len) override {
      auto &header = *(const IPv4::Header *)buf;
      int protocol = header.protocol;
      printf("IPv4 Packet length %d\n", len);
      printf("    dst " IPV4_ADDR_FMT_STRING ", src " IPV4_ADDR_FMT_STRING
             ", protocol 0x%02X, TTL %d\n",
             IPV4_ADDR_FMT_ARGS(header.dst), IPV4_ADDR_FMT_ARGS(header.src),
             protocol, header.timeToLive);

      return 0;
    }
  } handler;

public:
  CmdCapturePackets() : Command("capture-packets") {}

  int main(int argc, char **argv) override {
    ipv4.addRecvCallback(&handler);
    return 0;
  }
};
