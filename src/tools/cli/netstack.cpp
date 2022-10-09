#include <mutex>

#include "netstack.h"

NetBase netBase;
Ethernet ethernet(netBase);
IPv4 ipv4(ethernet);
LpmRouting routing;

IPv4Forward ipv4Forward(ipv4);

std::thread *netThread = nullptr;
LoopDispatcher loopDispatcher;

static std::mutex *loopRunning;

static void netThreadHandler() {
  netBase.loop();
  fprintf(stderr, "Loop breaked\n");
  loopRunning->unlock();
}

int startLoop() {
  if (netThread) {
    if (!loopRunning->try_lock()) {
      fprintf(stderr, "Loop is already running\n");
      return -1;
    }
    netThread->join();
    delete netThread;
    netThread = nullptr;
  }

  if (!loopRunning) {
    loopRunning = new std::mutex;
    loopRunning->lock();
  }
  netThread = new std::thread(netThreadHandler);
  return 0;
}

int initNetStack() {
  int rc;

  if ((rc = netBase.setup()) != 0 || (rc = ethernet.setup()) != 0 ||
      (rc = ipv4.setup()) != 0) {
    return 1;
  }

  ipv4.setRouting(&routing);
  netBase.addLoopCallback(&loopDispatcher);

  return startLoop();
}

void stopNetStack() {
  if (netThread) {
    auto task = LoopCallback::wrap([]() -> int { return 1; });
    loopDispatcher.invoke(&task);
    netThread->join();
    delete netThread;
    netThread = nullptr;
  }
}
