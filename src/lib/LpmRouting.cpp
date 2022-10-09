#include "log.h"

#include "LpmRouting.h"

LpmRouting::HopInfo LpmRouting::match(const Addr &addr) {
  Addr curMask = {0};
  HopInfo result{device : nullptr, dstMAC : {}};
  for (auto &&e : table)
    if ((addr & e.mask) == e.addr && (e.mask & curMask) == curMask) {
      result = {device : e.device, dstMAC : e.dstMAC};
      curMask = e.mask;
    }
  return result;
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
