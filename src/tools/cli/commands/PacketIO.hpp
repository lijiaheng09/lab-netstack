#include "netstack.h"
#include "commands.h"

class CmdCapturePackets : public Command {
  class Handler : public IP::RecvCallback {
  public:
    Handler() : IP::RecvCallback(true, -1) {}

    int handle(const void *buf, int len) override {
      auto &header = *(const IP::Header *)buf;
      int protocol = header.protocol;
      printf("IP Packet length %d\n", len);
      printf("    dst " IP_ADDR_FMT_STRING ", src " IP_ADDR_FMT_STRING
             ", protocol 0x%02X, TTL %d\n",
             IP_ADDR_FMT_ARGS(header.dst), IP_ADDR_FMT_ARGS(header.src),
             protocol, header.timeToLive);

      return 0;
    }
  } handler;

public:
  CmdCapturePackets() : Command("capture-packets") {}

  int main(int argc, char **argv) override {
    invoke([&]() { ip.addRecvCallback(&handler); });
    return 0;
  }
};
