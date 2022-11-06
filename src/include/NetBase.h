#ifndef NETSTACK_NET_STACK_H
#define NETSTACK_NET_STACK_H

#include <functional>
#include <atomic>
#include <mutex>
#include <shared_mutex>

#include "utils.h"
#include "TaskDispatcher.h"
#include "Timer.h"

/**
 * @brief Base of the netstack, handling sending & receiving of pcap devices.
 * May build services for devices of specific linkType above it.
 */
class NetBase {
public:
  TaskDispatcher dispatcher;
  Timer timer;

  NetBase() = default;
  NetBase(const NetBase &) = delete;

  class Device {
    struct pcap *p;
    friend class NetBase;

  public:
    const char *const name; // Name of the device.
    const int linkType;     // Type of its link layer.

    Device(struct pcap *p_, const char *name_, int linkType_);
    Device(const Device &) = delete;
    virtual ~Device();
  };

  /**
   * @brief Add a device to the netstack.
   *
   * @param device The device.
   */
  void addDevice(Device *device);

  /**
   * @brief Find an added device by its name.
   *
   * @param name Name of the device.
   * @return The device, `nullptr` if not found.
   */
  Device *findDeviceByName(const char *name);

  /**
   * @brief Send a frame through the device.
   *
   * @param buf Pointer to the frame.
   * @param len Length of the frame.
   * @param dev The device.
   * @return 0 on success, negative on error.
   */
  int send(const void *buf, size_t len, Device *dev);

  struct RecvInfo {
    Device *device;    // The receiving device.
    timeval timestamp; // The frame timestamp.
  };

  /**
   * @brief Handle a receiving frame.
   *
   * @param buf Pointer to the frame.
   * @param len Length of the frame.
   * @param info Other information.
   *
   * @return 0 on normal, 1 to remove the handler.
   */
  using RecvHandler =
      std::function<int(const void *buf, size_t len, const RecvInfo &info)>;

  /**
   * @brief Add a handler for receiving frames.
   *
   * @param handler The handler.
   * @param linkType The matched link-layer header type.
   */
  void addOnRecv(RecvHandler handler, int linkType);

  /**
   * @brief Handle a receiving frame.
   *
   * @param buf Pointer to the frame.
   * @param len Length of the frame.
   * @param info Other information.
   */
  void handleRecv(const void *buf, size_t len, const RecvInfo &info);

  /**
   * @brief Setup the netstack base.
   *
   * @return 0 on success, negative on error.
   */
  int setup();

  /**
   * @brief Start to loop for receiving.
   *
   * @return 0 if breaked normally, negative on error.
   */
  int loop();

  /**
   * @brief Asynchronously break the loop.
   */
  void asyncBreakLoop();

private:
  Vector<Device *> devices;
  HashMultiMap<int, RecvHandler> onRecv;

  std::atomic<bool> breaking;
};

#endif
