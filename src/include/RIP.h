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
  NetBase &netBase;

  RIP(UDP &udp_, NetworkLayer &network_, NetBase &netBase_,
      Timer::Duration updateCycle = 30s, Timer::Duration expireCycle = 180s,
      Timer::Duration cleanCycle = 120s);
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
    Timer::Task *expire;
  };

  int setup();

  int setEntry(const Addr &addr, const Addr &mask, const TabEntry &entry);

  int query(const Addr &addr, HopInfo &res) override;

  int sendRequest();
  int sendUpdate();

  struct Key {
    NetworkLayer::Addr addr;
    NetworkLayer::Addr mask;
    friend bool operator==(const Key &a, const Key &b) {
      return a.addr == b.addr && a.mask == b.mask;
    }
  };

  using Table = HashMap<Key, TabEntry>;

  const Table &getTable();

  void setCycles(Timer::Duration updateCycle, Timer::Duration expireCycle,
                 Timer::Duration cleanCycle);

private:
  Timer::Duration updateCycle, expireCycle, cleanCycle;

  Table table;
  LpmRouting matchTable;

  void handleRecv(const void *msg, size_t msgLen, const UDP::RecvInfo &info);

  Timer::Task *updateTask;

  void handleExpireTimer(Table::iterator entry);
  void handleCleanTimer(Table::iterator entry);
  void handleUpdateTimer();
};

#endif
