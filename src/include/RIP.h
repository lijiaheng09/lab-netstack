#ifndef NETSTACK_RIP_H
#define NETSTACK_RIP_H

#include <unordered_map>

#include "NetBase.h"
#include "UDP.h"

/**
 * @brief (Modified) Routing Information Protocol based on UDP.
 */
class RIP : public IP::Routing {
public:
  using NetworkLayer = IP;
  using LinkLayer = Ethernet;

  static const int UDP_PORT;

  static const int ADDRESS_FAMILY;

  static const int METRIC_INF;

  UDP &udp;
  NetworkLayer &network;
  NetBase &netBase;

  int updateCycle, expireCycle;

  RIP(UDP &udp_, NetworkLayer &network_, NetBase &netBase_);
  RIP(const RIP &) = delete;

  struct Header {
    uint8_t command;
    uint8_t version;
    uint16_t zero0;
    uint16_t addressFamily;
    uint16_t zero1;
  };

  struct DataEntry {
    NetworkLayer::Addr address;
    uint32_t zero0;
    uint32_t zero1;
    uint32_t metric;
  };

  struct TabEntry {
    LinkLayer::Device *device;
    LinkLayer::Addr dstMAC;
    int metric;
    time_t expireTime;
  };

  int setup();

  HopInfo match(const Addr &addr) override;

  int sendUpdate();

private:
  class HashAddr {
  public:
    size_t operator()(const NetworkLayer::Addr &a) const {
      return a.num;
    }
  };

  std::unordered_map<NetworkLayer::Addr, TabEntry, HashAddr> table;

  class UDPHandler : public UDP::RecvCallback {
    RIP &rip;

  public:
    UDPHandler(RIP &rip_);

    int handle(const void *buf, int len, const Info &info) override;
  } udpHandler;

  class LoopHandler : public LoopCallback {
    time_t updateTime;
    RIP &rip;

  public:
    LoopHandler(RIP &rip_);

    int handle() override;
  } loopHandler;
};

#endif
