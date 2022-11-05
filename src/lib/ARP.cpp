#include <arpa/inet.h>

#include "ARP.h"

#include "log.h"

ARP::ARP(L2 &l2_, L3 &l3_) : l2(l2_), l3(l3_) {}

const HashMap<ARP::L3::Addr, ARP::TabEntry> &ARP::getTable() {
  return table;
}

int ARP::sendRequest(L3::Addr target) {
  int rc = 0;
  for (auto &&e : l3.getAddrs()) {
    Packet packet{.hrd = htons(HRD),
                  .pro = htons(PRO),
                  .hln = HLN,
                  .pln = PLN,
                  .op = htons(OP_REQUEST),
                  .sha = e.device->addr,
                  .spa = e.addr,
                  .tha = {0},
                  .tpa = target};
    int rc1 =
        l2.send(&packet, sizeof(Packet), L2::BROADCAST, PROTOCOL_ID, e.device);
    if (rc1 < 0)
      rc = rc1;
  }
  return rc;
}

int ARP::query(L3::Addr target, L2::Addr &res) {
  time_t curTime = time(nullptr);
  auto p = table.find(target);
  if (p != table.end()) {
    res = p->second.linkAddr;
    if (curTime >= p->second.expireTime) {
      table.erase(p);
      sendRequest(target);
    }
    return 0;
  }
  int rc = sendRequest(target);
  if (rc != 0)
    return rc;
  return E_WAIT_FOR_TRYAGAIN;
}

void ARP::addWait(L3::Addr addr, WaitHandler handler, time_t timeout) {
  if (table.count(addr)) {
    handler(true);
  } else {
    sendRequest(addr);
    waiting.insert(
        {addr, WaitingEntry{.handler = handler,
                            .timeoutTime = time(nullptr) + timeout}});
  }
}

int ARP::setup() {
  l2.addOnRecv(
      [this](auto &&...args) -> int {
        handleRecv(args...);
        return 0;
      },
      PROTOCOL_ID);
  return 0;
}

void ARP::handleRecv(const void *buf, size_t len, const L2::RecvInfo &info) {
  if (len < sizeof(Packet)) {
    LOG_ERR("Truncated ARP packet: %lu/%lu", len, sizeof(Packet));
    return;
  }
  const Packet &packet = *(const Packet *)buf;
  Packet reply{.hrd = htons(HRD),
               .pro = htons(PRO),
               .hln = HLN,
               .pln = PLN,
               .op = htons(OP_RESPONSE)};
  if (packet.hrd == reply.hrd && packet.pro == reply.pro &&
      packet.hln == reply.hln && packet.pln == reply.pln) {
    if (packet.op == htons(OP_REQUEST)) {
      for (auto &&e : l3.getAddrs())
        if (packet.tpa == e.addr) {
          reply.tha = packet.sha;
          reply.tpa = packet.spa;
          reply.spa = e.addr;
          reply.sha = info.device->addr;
          l2.send(&reply, sizeof(Packet), packet.sha, PROTOCOL_ID, info.device);
        }

    } else if (packet.op == htons(OP_RESPONSE)) {
      time_t curTime = time(nullptr);
      table[packet.spa] = {.linkAddr = packet.sha,
                           .expireTime = curTime + EXPIRE_CYCLE};
      auto r = waiting.equal_range(packet.spa);
      for (auto it = r.first; it != r.second; it++) {
        it->second.handler(true);
      }
      waiting.erase(r.first, r.second);
    }
  }
}
