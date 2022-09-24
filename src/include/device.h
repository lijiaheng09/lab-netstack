/**
 * @file device.h
 * @brief Library supporting network device management.
 */

#ifndef LAB_NETSTACK_DEVICE_H
#define LAB_NETSTACK_DEVICE_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Add a device to the library for sending/receiving packets.
 * @param device Name of network device to send/receive packet on.
 * @return A non-negative _device-ID_ on success, -1 on error.
 */
int addDevice(const char *device);

/**
 * Find a device added by `addDevice`.
 * @param device Name of the network device.
 * @return A non-negative _device-ID_ on success, -1 if no such device
 * was found.
 */
int findDevice(const char *device);

#ifdef __cplusplus
}
#endif

#endif
