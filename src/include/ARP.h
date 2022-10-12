#ifndef NETSTACK_ARP_H
#define NETSTACK_ARP_H

#include <functional>
#include <unordered_map>

#include "Errors.h"
#include "utils.h"

#include "Ethernet.h"
#include "IP.h"

class ARP {
public:
  using LinkLayer = Ethernet;
  using NetworkLayer = IP;

  static constexpr int PROTOCOL_ID = 0x0806;

  static constexpr uint16_t HRD = 1;
  static constexpr uint16_t PRO = 0x0800;
  static constexpr uint8_t HLN = sizeof(LinkLayer::Addr);
  static constexpr uint8_t PLN = sizeof(NetworkLayer::Addr);

  static constexpr uint16_t OP_REQUEST = 1;
  static constexpr uint16_t OP_RESPONSE = 2;

  static constexpr time_t EXPIRE_CYCLE = 1200;

  struct Header {
    uint16_t hrd;           // Hardware address space.
    uint16_t pro;           // Protocol address space.
    uint8_t hln;            // byte length of each hardware address.
    uint8_t pln;            // byte length of each protocol address.
    uint16_t op;            // opcode (ares_op$REQUEST | ares_op$REPLY).
    LinkLayer::Addr sha;    // Hardware address of sender.
    NetworkLayer::Addr spa; // Protocol address of sender.
    LinkLayer::Addr tha;    // Hardware address of target.
    NetworkLayer::Addr tpa; // Protocol address of target.
  } __attribute__((packed));

  LinkLayer &linkLayer;
  NetworkLayer &network;

  ARP(LinkLayer &linkLayer_, NetworkLayer &network_);

  struct Entry {
    time_t expireTime;
    LinkLayer::Addr linkAddr;
  };

  class HashAddr {
  public:
    size_t operator()(const NetworkLayer::Addr &a) const {
      return a.num;
    }
  };

  using Table = std::unordered_map<NetworkLayer::Addr, Entry, HashAddr>;

  const Table &getTable();

  int sendRequest(NetworkLayer::Addr target);

  /**
   * @brief Match for link layer address.
   * 
   * @param netAddr The target.
   * @param linkAddr The result.
   * @param waitingCallback callback after waiting, when E_WAIT_FOR_TRYAGAIN returns.
   * @return 0 on success, negative on error.
   * Including: E_WAIT_FOR_TRYAGAIN
   */
  int match(NetworkLayer::Addr netAddr, LinkLayer::Addr &linkAddr, std::function<void ()> waitingCallback);

  int setup();

private:
  Table table;

  struct WaitingInfo {
    NetworkLayer::Addr addr;
    time_t timeoutTime;
    std::function<void ()> handler;
  };

  Vector<WaitingInfo> waiting;

  class LinkLayerHandler : public LinkLayer::RecvCallback {
    ARP &arp;

  public:
    LinkLayerHandler(ARP &arp_);
    int handle(const void *packet, int packetCapLen, const Info &info) override;
  } linkLayerHandler;
};

#endif
