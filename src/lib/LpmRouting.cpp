#include "log.h"

#include "LpmRouting.h"


LpmRouting::LpmRouting(ARP &arp_) : arp(arp_) {}

int LpmRouting::match(const Addr &addr, HopInfo &res, std::function<void ()> waitingCallback) {
  int rc = -1; 
  Addr curMask = {0};
  Addr gateway;
  for (auto &&e : table)
    if ((addr & e.mask) == e.addr && (e.mask & curMask) == curMask) {
      res.device = e.device;
      gateway = e.gateway;
      curMask = e.mask;
      rc = 0;
    }
  if (rc == 0) {
    Addr nextAddr = gateway == Addr{0} ? addr : gateway;
    rc = arp.match(nextAddr, res.dstMAC, waitingCallback);
  }
  return rc;
}

int LpmRouting::setEntry(const Entry &entry) {
  Addr newMask = {0};
  bool inPrefix = true;
  for (int i = 0; i < sizeof(Addr); i++) {
    uint8_t x = entry.mask.data[i];
    uint8_t lowbit = x & (~x + 1);
    if ((!inPrefix && x != 0) || (uint8_t)(x + lowbit) != 0) {
      ERRLOG("Invalid prefix mask: " IP_ADDR_FMT_STRING "\n",
             IP_ADDR_FMT_ARGS(entry.mask));
      return 1;
    }
    if (x != 0xFF)
      inPrefix = false;
  }

  for (auto &e : table)
    if (e.addr == entry.addr && e.mask == entry.mask) {
      e = entry;
      return 0;
    }

  table.push_back(entry);
  return 0;
}

int LpmRouting::delEntry(Addr addr, Addr mask) {
  for (auto it = table.begin(); it != table.end(); it++) {
    if (it->addr == addr && it->mask == mask) {
      table.erase(it);
      return 0;
    }
  }
  return 1;
}

const Vector<LpmRouting::Entry> &LpmRouting::getTable() {
  return table;
}
