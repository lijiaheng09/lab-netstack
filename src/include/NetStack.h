#ifndef NETSTACK_NET_STACK_H
#define NETSTACK_NET_STACK_H

#include "utils.h"

class NetStack {
public:
  NetStack() = default;
  NetStack(const NetStack &) = delete;

  class Device {
    struct pcap *p;

  public:
    char *const name;
    const int linkType;

    Device(struct pcap *p_, const char *name_, int linkType_);
    Device(const Device &) = delete;
    virtual ~Device();

    /**
     * @brief Send a frame through the device.
     *
     * @param buf Pointer to the frame.
     * @param len Length of the frame.
     * @return 0 on success, negative on error.
     */
    int sendFrame(void *buf, int len);

    friend class NetStack;
  };

  /**
   * @brief Add a device to the netstack.
   *
   * @param device Pointer to the `NetStack::Device` object.
   * @return Non-negative ID of the added device.
   */
  int addDevice(Device *device);

  /**
   * @brief Find an added device ID by its name.
   *
   * @param name Name of the device.
   * @return Pointer to the `NetStack::Device` object, nullptr if not found.
   */
  Device *findDeviceByName(const char *name);

  class RecvCallback {
  public:
    int linkType; // The matching linkType, -1 for any.

    /**
     * @brief Construct a new RecvCallback object.
     *
     * @param linkType_ The matching linkType, -1 for any.
     */
    RecvCallback(int linkType_);

    /**
     * @brief Handle a received frame.
     *
     * @param buf Pointer to the frame.
     * @param len Length of the frame.
     * @param device Pointer to a `NetStack::Device` object, describing the
     * receiving device.
     * @return 0 on success, negative on error.
     */
    virtual int handle(const void *buf, int len, Device *device) = 0;
  };

  void addRecvCallback(RecvCallback *callback);

  int handleFrame(const void *buf, int len, Device *device);

  /**
   * @brief Setup the netstack.
   *
   * @return 0 on success, negative on error.
   */
  int setup();

  /**
   * @brief Start to loop for receiving.
   *
   * @return negative on error.
   */
  int loop();

private:
  Vector<Device *> devices;
  Vector<RecvCallback *> callbacks;
};

#endif
