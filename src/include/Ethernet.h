#ifndef NETSTACK_ETHERNET_H
#define NETSTACK_ETHERNET_H

#include <cinttypes>

#include "utils.h"
#include "NetStack.h"

class Ethernet {
public:
  static const int LINK_TYPE;

  struct Addr {
    unsigned char data[6];
  };

  struct Header {
    Addr dst;
    Addr src;
    uint16_t etherType;
  };

  NetStack &stack;
  Ethernet(NetStack &stack_);
  Ethernet(const Ethernet &) = delete;

  class Device : public NetStack::Device {
  public:
    const Addr addr;
    Device(struct pcap *p_, const char *name_, const Addr &addr_);

    /**
     * @brief Send a frame through the Ethernet device.
     *
     * @param buf Pointer to the payload.
     * @param len Length of the payload.
     * @param dst The Ethernet address of the destination.
     * @param etherType The etherType field.
     * @return 0 on success, negative on error.
     */
    int sendFrame(void *buf, int len, const Addr &dst, int etherType);
  };

  /**
   * @brief Add an Ethernet device to the netstack.
   * 
   * @param name Name of the device.
   * @return Pointer to the added `Ethernet::Device` object, nullptr on error.
   */
  Device *addDeviceByName(const char *name);

  /**
   * @brief Find an added Ethernet device ID by its name.
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

    /**
     * @brief Handle a received Ethernet frame.
     * 
     * @param buf Pointer to the frame.
     * @param len Length of the frame.
     * @param device Pointer to a `Ethernet::Device` object, describing the
     * receiving device.
     * @return 0 on success, negative on error.
     */
    virtual int handle(const void *buf, int len, Device *device) = 0;
  };

  void addRecvCallback(RecvCallback *callback);

  int handleFrame(const void *buf, int len, Device *device);

  /**
   * @brief Setup the Ethernet Layer.
   * 
   * @param stack The base netstack.
   * @return 0 on success, negative on error.
   */
  int setup();

private:
  class NetStackHandler : public NetStack::RecvCallback {
    Ethernet &ethernetLayer;
  public:
    NetStackHandler(Ethernet &ethernetLayer_);
    int handle(const void *buf, int len, NetStack::Device *device) override;
  } netstackHandler;

  Vector<RecvCallback *> callbacks;
};

#endif
