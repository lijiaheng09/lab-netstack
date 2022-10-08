#ifndef NETSTACK_IPV4_FORWARD_H
#define NETSTACK_IPV4_FORWARD_H

#include "IPv4.h"

class IPv4Forward {
public:
  IPv4 &ipv4Layer;

  IPv4Forward(IPv4 &ipv4Layer_);
  IPv4Forward(const IPv4Forward &) = delete;

  /**
   * @brief Setup the IPv4 forwarding service.
   * 
   * @return 0 on success, negative on error.
   */
  int setup();

private:
  class IPv4Handler : public IPv4::RecvCallback {
    IPv4Forward &service;
  public:
    IPv4Handler(IPv4Forward &service_);
    int handle(const void *buf, int len);
  } ipv4Handler;
};

#endif
