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
  static const int LINK_TYPE; // The corresponding linkType in netBase.

  struct Addr {
    unsigned char data[6];

    static const Addr BROADCAST;
  };

  struct Header {
    Addr dst;
    Addr src;
    uint16_t etherType;
  };

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
   * @brief Add an Ethernet device to the netstack.
   *
   * @param name Name of the device.
   * @return Pointer to the added `Ethernet::Device` object, nullptr on error.
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
  int send(const void *data, size_t dataLen, Addr dst, uint16_t etherType, Device *dev);

  class RecvCallback {
  public:
    int etherType; // The matching etherType, -1 for any.

    /**
     * @brief Construct a new RecvCallback object.
     *
     * @param etherType_ The matching etherType, -1 for any.
     */
    RecvCallback(int etherType_);

    struct Info {
      timeval timestamp;

      Device *linkDevice;
      const Header *linkHeader;
    };

    /**
     * @brief Handle a received Ethernet frame (guaranteed valid).
     *
     * @param data Pointer to the payload.
     * @param dataLen Length of the payload.
     * @param info Other information of the received frame.
     * @return 0 on success, negative on error.
     */
    virtual int handle(const void *data, int dataLen, const Info &info) = 0;
  };

  /**
   * @brief Register a callback on receiving Ethernet frames.
   *
   * @param callback Pointer to a `RecvCallback` object (which need to be
   * persistent).
   */
  void addRecvCallback(RecvCallback *callback);

  /**
   * @brief Handle a receiving frame from `NetBase`.
   *
   * @param frame Pointer to the frame.
   * @param frameLen Length of the frame.
   * @param info Other information.
   */
  void handleRecv(const void *frame, int frameLen, const NetBase::RecvInfo &info);

  /**
   * @brief Setup the Ethernet link layer service.
   *
   * @return 0 on success, negative on error.
   */
  int setup();

private:
  Vector<RecvCallback *> callbacks;
};

#endif
