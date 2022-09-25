/**
 * @file netstack.h
 * @brief A userspace protocol stack based on libpcap
 */

#ifndef LAB_NETSTACK_NETSTACK_H
#define LAB_NETSTACK_NETSTACK_H

#include "device.h"
#include "packetio.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialize the netstack.
 * @return 0 on success, -1 on failure.
 */
int netstackInit(void);

#ifdef __cplusplus
}
#endif

#endif
