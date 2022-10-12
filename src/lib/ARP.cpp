#include <arpa/inet.h>

#include "ARP.h"

#include "log.h"

ARP::ARP(LinkLayer &linkLayer_, NetworkLayer &network_)
    : linkLayer(linkLayer_), network(network_), linkLayerHandler(*this) {}

const ARP::Table &ARP::getTable() {
  return table;
}

int ARP::sendRequest(NetworkLayer::Addr target) {
  int rc;
  for (auto &&e : network.getAddrs()) {
    Header header{
      hrd : htons(HRD),
      pro : htons(PRO),
      hln : HLN,
      pln : PLN,
      op : htons(OP_REQUEST),
      sha : e.device->addr,
      spa : e.addr,
      tha : {0},
      tpa : target
    };
    int rc1 = e.device->sendFrame(&header, sizeof(Header),
                                  Ethernet::Addr::BROADCAST, PROTOCOL_ID);
    if (rc1 < 0)
      rc = rc1;
  }
  return rc;
}

int ARP::match(NetworkLayer::Addr netAddr, LinkLayer::Addr &linkAddr, std::function<void ()> waitingCallback) {
  time_t curTime = time(nullptr);
  auto p = table.find(netAddr);
  if (p != table.end()) {
    if (curTime >= p->second.expireTime) {
      table.erase(p);
    } else {
      linkAddr = p->second.linkAddr;
      return 0;
    }
  }
  sendRequest(netAddr);
  if (waitingCallback)
    waiting.push_back({
      addr: netAddr,
      timeoutTime: 0, // No timeout now
      handler: waitingCallback
    });
  return E_WAIT_FOR_TRYAGAIN;
}

int ARP::setup() {
  linkLayer.addRecvCallback(&linkLayerHandler);
  return 0;
}

ARP::LinkLayerHandler::LinkLayerHandler(ARP &arp_)
    : LinkLayer::RecvCallback(PROTOCOL_ID), arp(arp_) {}

int ARP::LinkLayerHandler::handle(const void *packet, int packetCapLen,
                                  const Info &info) {
  if (packetCapLen < sizeof(Header)) {
    ERRLOG("Truncated ARP packet: %d/%d", packetCapLen, (int)sizeof(Header));
    return -1;
  }
  const Header &header = *(const Header *)packet;
  Header replyHeader{
    hrd : htons(HRD),
    pro : htons(PRO),
    hln : HLN,
    pln : PLN,
    op : htons(OP_RESPONSE)
  };
  int rc = 0;
  if (header.hrd == replyHeader.hrd && header.pro == replyHeader.pro &&
      header.hln == replyHeader.hln && header.pln == replyHeader.pln) {
    if (header.op == htons(OP_REQUEST)) {
      for (auto &&e : arp.network.getAddrs())
        if (header.tpa == e.addr) {
          replyHeader.tha = header.sha;
          replyHeader.tpa = header.spa;
          replyHeader.spa = e.addr;
          replyHeader.sha = info.linkDevice->addr;
          if (info.linkDevice->sendFrame(&replyHeader, sizeof(Header),
                                         header.sha, PROTOCOL_ID) < 0) {
            rc = -1;
          }
        };

    } else if (header.op == htons(OP_RESPONSE)) {
      time_t curTime = time(nullptr);
      arp.table[header.spa] = {curTime + EXPIRE_CYCLE, header.sha};
      for (auto it = arp.waiting.begin(); it != arp.waiting.end(); ) {
        if (curTime >= it->timeoutTime || it->addr == header.spa) {
          it->handler();
          it = arp.waiting.erase(it);
        } else {
          it++;
        }
      }
    }
  }
  return rc;
}
