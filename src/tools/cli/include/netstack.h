#ifndef TOOLS_NETSTACK_H
#define TOOLS_NETSTACK_H

#include "NetBase.h"
#include "Ethernet.h"
#include "IPv4.h"
#include "IPv4Forward.h"
#include "LpmRouting.h"

extern NetBase netBase;
extern Ethernet ethernet;
extern IPv4 ipv4;
extern LpmRouting routing;

extern IPv4Forward ipv4Forward;

/**
 * @brief Initialize the netstack.
 * 
 * @return 0 on success, negative on error.
 */
int initNetStack();

#endif
