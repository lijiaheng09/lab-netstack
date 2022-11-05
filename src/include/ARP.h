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
  using L2 = Ethernet;
  using L3 = IP;

  static constexpr int PROTOCOL_ID = 0x0806;

  static constexpr uint16_t HRD = L2::LINK_TYPE;
  static constexpr uint16_t PRO = L3::PROTOCOL_ID;
  static constexpr uint8_t HLN = sizeof(L2::Addr);
  static constexpr uint8_t PLN = sizeof(L3::Addr);

  static constexpr uint16_t OP_REQUEST = 1;
  static constexpr uint16_t OP_RESPONSE = 2;

  static constexpr time_t EXPIRE_CYCLE = 1200;

  struct Packet {
    uint16_t hrd; // Hardware address space.
    uint16_t pro; // Protocol address space.
    uint8_t hln;  // byte length of each hardware address.
    uint8_t pln;  // byte length of each protocol address.
    uint16_t op;  // opcode (ares_op$REQUEST | ares_op$REPLY).
    L2::Addr sha; // Hardware address of sender.
    L3::Addr spa; // Protocol address of sender.
    L2::Addr tha; // Hardware address of target.
    L3::Addr tpa; // Protocol address of target.
  } __attribute__((packed));

  L2 &l2;
  L3 &l3;

  ARP(L2 &l2_, L3 &l3_);
  ARP(const ARP &) = delete;

  /**
   * @brief Query for L2 address of a L3 target.
   *
   * @param target The L3 target of query.
   * @param res The result.
   * @return 0 on success, negative on error.
   * Including: E_WAIT_FOR_TRYAGAIN
   */
  int query(L3::Addr target, L2::Addr &res);

  /**
   * @brief Handle the result of waiting.
   *
   * @param succ If the query is available now.
   */
  using WaitHandler = std::function<void(bool succ)>;

  /**
   * @brief Wait for the query for a L3 target being available.
   *
   * @param addr The L3 target of query.
   * @param handler The handler after waiting.
   * @param timeout The waiting timeout (TODO).
   */
  void addWait(L3::Addr addr, WaitHandler handler, time_t timeout = 60);

  /**
   * @brief Setup the RIP service.
   *
   * @return 0 on success, negative on error.
   */
  int setup();

  struct TabEntry {
    L2::Addr linkAddr;
    time_t expireTime;
  };

  const HashMap<L3::Addr, TabEntry> &getTable();

private:
  HashMap<L3::Addr, TabEntry> table;

  struct WaitingEntry {
    WaitHandler handler;
    time_t timeoutTime;
  };

  HashMultiMap<L3::Addr, WaitingEntry> waiting;

  int sendRequest(L3::Addr target);

  void handleRecv(const void *buf, size_t len, const L2::RecvInfo &info);
};

#endif
