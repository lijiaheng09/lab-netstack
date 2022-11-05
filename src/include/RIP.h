#ifndef NETSTACK_RIP_H
#define NETSTACK_RIP_H

#include <unordered_map>

#include "NetBase.h"
#include "UDP.h"

#include "LpmRouting.h"

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
  ARP &arp;
  NetBase &netBase;

  int updateCycle, expireCycle, cleanCycle;

  RIP(UDP &udp_, NetworkLayer &network_, ARP &arp_, NetBase &netBase_);
  RIP(const RIP &) = delete;

  struct Header {
    uint8_t command;
    uint8_t version;
    uint16_t zero;
  };

  struct DataEntry {
    uint16_t addressFamily;
    uint16_t zero0;
    Addr address;
    Addr mask;
    uint32_t zero2;
    uint32_t metric;
  };

  struct TabEntry {
    LinkLayer::Device *device;
    Addr gateway;
    int metric;
    time_t expireTime;
  };

  int setup();

  int setEntry(const Addr &addr, const Addr &mask, const TabEntry &entry);

  int match(const Addr &addr, HopInfo &res, std::function<void ()> waitingCallback) override;

  int sendRequest();
  int sendUpdate();

  struct Key {
    NetworkLayer::Addr addr;
    NetworkLayer::Addr mask;
    friend bool operator ==(const Key &a, const Key &b) {
      return a.addr == b.addr && a.mask == b.mask;
    }
  };

  class HashAddr {
  public:
    size_t operator()(const Key &a) const {
      return (uint64_t)a.mask.num << 32 | a.addr.num;
    }
  };

  using Table = std::unordered_map<Key, TabEntry, HashAddr>;

  const Table &getTable();

private:
  Table table;
  LpmRouting matchTable;

  time_t updateTime;

  bool isUp;

  void handleRecv(const void *msg, size_t msgLen, const UDP::RecvInfo &info);

  class LoopHandler : public LoopCallback {
    RIP &rip;

  public:
    LoopHandler(RIP &rip_);

    int handle() override;
  } loopHandler;
};

#endif
