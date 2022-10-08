#ifndef NETSTACK_LPM_ROUTING_H
#define NETSTACK_LPM_ROUTING_H

#include "IPv4.h"

class LpmRouting : public IPv4::Routing {
public:
  HopInfo match(const Addr &addr) override;

  struct Entry {
    Addr addr;                 // The address to be matched.
    Addr mask;                 // The prefix mask (required to be a prefix).
    LinkLayer::Device *device; // The port to the next hop.
    LinkLayer::Addr dstMAC;   // The destination address of the next hop.
  };

  /**
   * @brief Set an routing entry
   * 
   * @param entry The entry to be set.
   * @return 0 on success, negative on error.
   */
  int setEntry(const Entry &entry);

private:
  Vector<Entry> table;
};

#endif
