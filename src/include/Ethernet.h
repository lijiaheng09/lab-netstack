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

    /**
     * @brief Send a frame through the Ethernet device.
     *
     * @param buf Pointer to the payload.
     * @param len Length of the payload.
     * @param dst Ethernet address of the destination.
     * @param etherType The `etherType` field.
     * @return 0 on success, negative on error.
     */
    int sendFrame(const void *buf, int len, const Addr &dst, int etherType);
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

  class RecvCallback {
  public:
    int etherType; // The matching etherType, -1 for any.

    /**
     * @brief Construct a new RecvCallback object.
     *
     * @param etherType_ The matching etherType, -1 for any.
     */
    RecvCallback(int etherType_);

    struct Info : public NetBase::RecvCallback::Info {
      Info(const NetBase::RecvCallback::Info &base)
          : NetBase::RecvCallback::Info(base) {}
    };

    /**
     * @brief Handle a received Ethernet frame (guaranteed valid).
     *
     * @param buf Pointer to the frame.
     * @param len Length of the frame.
     * @param device The receiving device.
     * @param info Other information of the received frame.
     * @return 0 on success, negative on error.
     */
    virtual int handle(const void *buf, int len, Device *device,
                       const Info &info) = 0;
  };

  /**
   * @brief Register a callback on receiving Ethernet frames.
   *
   * @param callback Pointer to a `RecvCallback` object (which need to be
   * persistent).
   */
  void addRecvCallback(RecvCallback *callback);

  /**
   * @brief Setup the Ethernet link layer service.
   *
   * @return 0 on success, negative on error.
   */
  int setup();

private:
  class NetBaseHandler : public NetBase::RecvCallback {
    Ethernet &ethernet;

  public:
    NetBaseHandler(Ethernet &ethernet_);
    int handle(const void *buf, int len, NetBase::Device *device,
               const Info &info) override;
  } netBaseHandler;

  Vector<RecvCallback *> callbacks;
};

#endif
