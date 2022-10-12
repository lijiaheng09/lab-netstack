#ifndef NETSTACK_LPM_ROUTING_H
#define NETSTACK_LPM_ROUTING_H

#include "IP.h"
#include "ARP.h"

/**
 * @brief The Longest Prefix Match (LPM) routing table.
 */
class LpmRouting : public IP::Routing {
public:
  ARP &arp;

  LpmRouting(ARP &arp_);

  int match(const Addr &addr, HopInfo &res,
            std::function<void()> waitingCallback) override;

  struct Entry {
    Addr addr;                 // The address to be matched.
    Addr mask;                 // The prefix mask (required to be a prefix).
    LinkLayer::Device *device; // The port to the next hop.
    Addr gateway; // The destination IP address of the next hop, 0 for local.
  };

  /**
   * @brief Set an routing entry
   *
   * @param entry The entry to be set.
   * @return 0 on success, negative on error.
   */
  int setEntry(const Entry &entry);

  int delEntry(Addr addr, Addr mask);

  const Vector<Entry> &getTable();

private:
  Vector<Entry> table;
};

#endif
