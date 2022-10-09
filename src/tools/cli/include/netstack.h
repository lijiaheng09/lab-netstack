#ifndef TOOLS_NETSTACK_H
#define TOOLS_NETSTACK_H

#include <thread>

#include "LoopDispatcher.h"

#include "NetBase.h"
#include "Ethernet.h"
#include "IP.h"
#include "IPForward.h"
#include "LpmRouting.h"

extern NetBase netBase;
extern Ethernet ethernet;
extern IP ip;
extern LpmRouting routing;

extern IPForward ipForward;

extern std::thread *netThread;
extern LoopDispatcher loopDispatcher;

/**
 * @brief Initialize the netstack.
 * 
 * @return 0 on success, negative on error.
 */
int initNetStack();

/**
 * @brief Start the netstack main loop.
 * 
 * @return 0 on success, negative on error.
 */
int startLoop();

/**
 * @brief Stop the netstack.
 */
void stopNetStack();

#endif
