#ifndef NETSTACK_LPM_ROUTING_H
#define NETSTACK_LPM_ROUTING_H

#include "IP.h"

/**
 * @brief The Longest Prefix Match (LPM) routing table.
 */
class LpmRouting : public IP::Routing {
public:
  HopInfo match(const Addr &addr) override;

  struct Entry {
    Addr addr;                 // The address to be matched.
    Addr mask;                 // The prefix mask (required to be a prefix).
    LinkLayer::Device *device; // The port to the next hop.
    LinkLayer::Addr dstMAC;    // The destination address of the next hop.
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
