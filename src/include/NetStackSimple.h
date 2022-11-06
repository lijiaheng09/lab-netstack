#ifndef NETSTACK_NETSTACK_SIMPLE_H
#define NETSTACK_NETSTACK_SIMPLE_H

#include <thread>

#include "TaskDispatcher.h"

#include "NetBase.h"
#include "Ethernet.h"
#include "IP.h"

class NetStackSimple {
public:
  NetBase netBase;
  Ethernet ethernet;
  IP ip;
  IP::Routing *routing;

  NetStackSimple();
  NetStackSimple(const NetStackSimple &) = delete;
  virtual ~NetStackSimple();

  /**
   * @brief Setup static LPM routing table.
   */
  void configStaticRouting();

  /**
   * @brief Automatically configure the netstack for use.
   * Need to be called before start looping, or in the thread of looping.
   *
   * @param setRouting If set the (static) routing table if possible.
   * @return 0 on success, negative on error.
   */
  int autoConfig(bool setRouting = false);

  /**
   * @brief Start the netstack loop.
   */
  void start();

  /**
   * @brief Terminate the netstack.
   */
  void stop();

  /**
   * @brief Wait for the netstack to terminate.
   */
  void wait();

  using Task = TaskDispatcher::Task;

  void invoke(Task task);
  void beginInvoke(Task task);

private:
  std::thread *netThread;
};

#endif
