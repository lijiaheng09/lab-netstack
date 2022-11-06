#include <cassert>
#include <cerrno>
#include <cstdlib>
#include <cstring>

#include <arpa/inet.h>

#include "log.h"
#include "RIP.h"

constexpr int RIP::UDP_PORT = 520;
constexpr int RIP::ADDRESS_FAMILY = 2;
constexpr int RIP::METRIC_INF = 16;

RIP::RIP(UDP &udp_, NetworkLayer &network_, NetBase &netBase_)
    : udp(udp_), network(network_), netBase(netBase_),
      updateCycle(30), expireCycle(180), cleanCycle(120), updateTime(0),
      isUp(false), matchTable() {}

int RIP::setup() {
  if (isUp) {
    ERRLOG("RIP is already running.\n");
    return 1;
  }
  isUp = true;
  udp.addOnRecv(
      [this](auto &&...args) -> int {
        handleRecv(args...);
        return 0;
      },
      UDP_PORT);
  netBase.addOnIter([this]() -> int {
    return handleIter();
  });
  sendRequest();
  sendUpdate();
  return 0;
}

int RIP::setEntry(const Addr &addr, const Addr &mask, const TabEntry &entry) {
  if (entry.metric > METRIC_INF) {
    ERRLOG("Too large metric: %d\n", entry.metric);
    return 1;
  }
  int rc = matchTable.setEntry({
    addr : addr,
    mask : mask,
    device : entry.device,
    gateway : entry.gateway
  });
  if (rc != 0)
    return rc;
  table[{addr, mask}] = entry;
  return 0;
}

int RIP::query(const Addr &addr, HopInfo &res) {
  return matchTable.query(addr, res);
}

int RIP::sendRequest() {
  UDP::L3::Addr srcAddr;
  if (udp.l3.getAnyAddr(nullptr, srcAddr) < 0) {
    ERRLOG("No IP address on the host.\n");
    return -1;
  }

  Header header = {command : 1, version : 0, zero : 0};

  return udp.sendSegment(&header, sizeof(Header), srcAddr, UDP_PORT,
                         NetworkLayer::BROADCAST, UDP_PORT);
}

int RIP::sendUpdate() {
  time_t curTime = time(nullptr);

  updateTime = curTime + updateCycle;

  UDP::L3::Addr srcAddr;
  if (udp.l3.getAnyAddr(nullptr, srcAddr) < 0) {
    ERRLOG("No IP address on the host.\n");
    return -1;
  }

  const auto &netAddrs = network.getAddrs();
  for (auto &&e : netAddrs) {
    table[{e.addr & e.mask, e.mask}] =
        {device : e.device, gateway : {0}, metric : 0, expireTime : 0};
    matchTable.setEntry({
      addr : e.addr & e.mask,
      mask : e.mask,
      device : e.device,
      gateway : {0}
    });
  }

  int dataLen = sizeof(Header) + sizeof(DataEntry) * (int)table.size();
  void *buf = malloc(dataLen);
  if (!buf) {
    ERRLOG("malloc error: %s\n", strerror(errno));
    return -1;
  }

  Header &header = *(Header *)buf;
  header = {command : 2, version : 0, zero : 0};
  DataEntry *p = (DataEntry *)(&header + 1);
  for (auto &&e : table) {
    *p++ = DataEntry{
      addressFamily : htons(ADDRESS_FAMILY),
      zero0 : 0,
      address : e.first.addr,
      mask : e.first.mask,
      zero2 : 0,
      metric : htonl(e.second.metric)
    };
  }

  int rc = udp.sendSegment(buf, dataLen, srcAddr, UDP_PORT,
                           NetworkLayer::BROADCAST, UDP_PORT);
  free(buf);
  return rc;
}

const RIP::Table &RIP::getTable() {
  return table;
}

void RIP::handleRecv(const void *msg, size_t msgLen, const UDP::RecvInfo &info) {
  if (msgLen < sizeof(Header)) {
    LOG_ERR("Truncated RIP header: %lu/%lu\n", msgLen, sizeof(Header));
    return;
  }
  const Header &header = *(const Header *)msg;

  Header requestHeader{command : 1, version : 0, zero : 0};
  if (memcmp(msg, &requestHeader, sizeof(Header)) == 0) {
    sendUpdate();
    return;
  }

  Header requriedHeader{command : 2, version : 0, zero : 0};
  if (memcmp(msg, &requriedHeader, sizeof(Header)) != 0) {
    LOG_ERR("Invalid RIP header.\n");
    return;
  }
  const DataEntry *ents = (const DataEntry *)(&header + 1);
  int nEntries = (msgLen - sizeof(Header)) / sizeof(DataEntry);

  bool realUpdated = false;

  time_t curTime = time(nullptr);
  for (int i = 0; i < nEntries; i++) {
    const auto &e = ents[i];
    if (ntohs(e.addressFamily) != ADDRESS_FAMILY)
      continue;

    int metric = ntohl(e.metric) + 1;
    if (metric > METRIC_INF)
      continue;

    // Ignore the local host.
    if (network.findDeviceByAddr(e.address))
      continue;

    bool updateEnt = false;
    if (!table.count({e.address, e.mask})) {
      updateEnt = true;
      realUpdated = true;
    } else {
      auto &&r = table[{e.address, e.mask}];
      if ((r.metric != 0 && r.gateway == info.l3.header->src) ||
          metric < r.metric) {
        updateEnt = true;
        if (metric != r.metric)
          realUpdated = true;
      }
    }

    if (updateEnt) {
      table[{e.address, e.mask}] = TabEntry{
        device : info.l2.device,
        gateway : info.l3.header->src,
        metric : metric,
        expireTime : curTime + expireCycle
      };
      if (metric < METRIC_INF) {
        matchTable.setEntry({
          addr : e.address,
          mask : e.mask,
          device : info.l2.device,
          gateway : info.l3.header->src,
        });
      } else {
        matchTable.delEntry(e.address, e.mask);
      }
    }
  }

  // Triggered updates
  if (realUpdated)
    sendUpdate();
}

int RIP::handleIter() {
  time_t curTime = time(nullptr);
  for (auto it = table.begin(); it != table.end();) {
    auto &e = *it;
    if (e.second.expireTime) {
      if (curTime > e.second.expireTime) {
        matchTable.delEntry(it->first.addr, it->first.mask);
        e.second.metric = METRIC_INF;
      }
      if (curTime - e.second.expireTime > cleanCycle) {
        it = table.erase(it);
        continue;
      }
    }
    it++;
  }
  if (curTime >= updateTime) {
    sendUpdate();
  }
  return 0;
}
