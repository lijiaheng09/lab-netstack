#ifndef NETSTACK_ETHERNET_H
#define NETSTACK_ETHERNET_H

#include <cinttypes>

#include "utils.h"

#include "NetBase.h"

#define ETHERNET_ADDR_FMT_STRING "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx"
#define ETHERNET_ADDR_FMT_ARGS(a)                                              \
  a.data[0], a.data[1], a.data[2], a.data[3], a.data[4], a.data[5]
#define ETHERNET_ADDR_FMT_NUM 6

/**
 * @brief The Ethernet link layer service built above `NetBase`.
 * Can open Ethernet devices and handling sending & receiving of Ethernet
 * frames.
 * May build network services based on etherType above it.
 */
class Ethernet {
public:
  static constexpr int LINK_TYPE = 1; // The corresponding linkType in netBase.

  struct Addr {
    unsigned char data[6];
  } __attribute__((packed));

  static constexpr Addr BROADCAST{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

  struct Header {
    Addr dst;
    Addr src;
    uint16_t etherType;
  } __attribute__((packed));

  NetBase &netBase;

  Ethernet(NetBase &netBase_);
  Ethernet(const Ethernet &) = delete;

  class Device : public NetBase::Device {
    Device(struct pcap *p_, const char *name_, const Addr &addr_);
    friend class Ethernet;

  public:
    const Addr addr; // Ethernet (MAC) address of the device.
  };

  /**
   * @brief Add an Ethernet device to the netstack by its name.
   *
   * @param name Name of the device.
   * @return The added device, `nullptr` on error.
   */
  Device *addDeviceByName(const char *name);

  /**
   * @brief Find an added Ethernet device by its name.
   *
   * @param name Name of the device.
   * @return Pointer to the `Ethernet::Device` object, nullptr if not found.
   */
  Device *findDeviceByName(const char *name);

  /**
   * @brief Send a frame through the device.
   *
   * @param data Pointer to the payload.
   * @param dataLen Length of the payload.
   * @param dst Destination address.
   * @param etherType
   * @param dev The device.
   * @return 0 on success, negative on error.
   */
  int send(const void *data, size_t dataLen, Addr dst, uint16_t etherType,
           Device *dev);

  struct RecvInfo {
    timeval timestamp;
    Device *device;
    const Header *header;
  };

  /**
   * @brief Handle a receiving Ethernet frame.
   *
   * @param data Pointer to the payload.
   * @param dataLen Length of the payload.
   * @param info Other information.
   *
   * @return 0 on normal, 1 to remove the handler.
   */
  using RecvHandler = std::function<int(const void *data, size_t dataLen,
                                        const RecvInfo &info)>;

  /**
   * @brief Add a handler for receiving frames.
   *
   * @param handler The handler.
   * @param linkType The matched `etherType` field.
   */
  void addOnRecv(RecvHandler handler, uint16_t etherType);

  /**
   * @brief Setup the Ethernet link layer service.
   *
   * @return 0 on success, negative on error.
   */
  int setup();

private:
  HashMultMap<uint16_t, RecvHandler> onRecv;

  void handleRecv(const void *frame, size_t frameLen,
                  const NetBase::RecvInfo &info);
};

#endif
