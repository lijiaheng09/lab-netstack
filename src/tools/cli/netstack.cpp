#include <mutex>

#include "netstack.h"

NetBase netBase;
Ethernet ethernet(netBase);
IP ip(ethernet);
LpmRouting staticRouting;
UDP udp(ip);
RIP ripRouting(udp, ip, netBase);

IPForward ipForward(ip);

std::thread *netThread = nullptr;

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
      (rc = ip.setup()) != 0 || (rc = udp.setup()) != 0) {
    return rc;
  }

  ip.setRouting(&staticRouting);

  return startLoop();
}

void stopLoop() {
  if (netThread) {
    netBase.asyncBreakLoop();
    netThread->join();
    delete netThread;
    netThread = nullptr;
  }
}
