#include <pcap/pcap.h>

#include <linux/if_arp.h>
#include <linux/if_packet.h>

#include "LpmRouting.h"
#include "NetStackSimple.h"

#include "log.h"

NetStackSimple::NetStackSimple()
    : netBase(), ethernet(netBase), ip(ethernet), routing(nullptr),
      netThread(nullptr) {
  int rc = 0;
  if ((rc = netBase.setup()) != 0 || (rc = ethernet.setup()) != 0 ||
      (rc = ip.setup()) != 0) {
    LOG_ERR("Netstack initialize failed");
    abort();
  }
}

NetStackSimple::~NetStackSimple() {
  if (netThread)
    stop();
  delete routing;
}

void NetStackSimple::configStaticRouting() {
  routing = new LpmRouting();
  ip.setRouting(routing);
}

int NetStackSimple::autoConfig(bool setRouting) {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *allDevs;
  if (pcap_findalldevs(&allDevs, errbuf) != 0) {
    LOG_ERR("pcap_findalldevs: %s", errbuf);
    return -1;
  }

  int nDevs = 0;

  for (auto *p = allDevs; p; p = p->next) {
    bool isEthernet = false;
    for (auto *a = p->addresses; a; a = a->next)
      if (a->addr && a->addr->sa_family == AF_PACKET) {
        sockaddr_ll *s = (sockaddr_ll *)a->addr;
        if (s->sll_hatype == ARPHRD_ETHER) {
          isEthernet = true;
          break;
        }
      }
    if (!isEthernet)
      continue;
    if (auto *d = ethernet.addDeviceByName(p->name)) {
      nDevs++;
      LOG_INFO("Device added: %s", d->name);
      LOG_INFO("    ether " ETHERNET_ADDR_FMT_STRING,
               ETHERNET_ADDR_FMT_ARGS(d->addr));
      for (auto *a = p->addresses; a; a = a->next)
        if (a->addr && a->addr->sa_family == AF_INET) {
          IP::Addr addr, mask;
          memcpy(&addr, &((sockaddr_in *)a->addr)->sin_addr, sizeof(IP::Addr));
          memcpy(&mask, &((sockaddr_in *)a->netmask)->sin_addr,
                 sizeof(IP::Addr));
          ip.addAddr({device : d, addr : addr, mask : mask});
          LOG_INFO("    inet " IP_ADDR_FMT_STRING
                   " netmask " IP_ADDR_FMT_STRING,
                   IP_ADDR_FMT_ARGS(addr), IP_ADDR_FMT_ARGS(mask));
        }
    }
  }
  pcap_freealldevs(allDevs);

  if (setRouting && !ip.getRouting()) {
    LOG_INFO("Setting static routing...");
    auto *r = new LpmRouting();
    for (auto &&e : ip.getAddrs()) {
      r->setEntry({.addr = e.addr & e.mask,
                  .mask = e.mask,
                  .device = e.device,
                  .gateway{0, 0, 0, 0}});
    }
    routing = r;
    ip.setRouting(r);
  }

  return 0;
}

void NetStackSimple::start() {
  if (netThread) {
    LOG_ERR("Netstack is already running");
    return;
  }
  netThread = new std::thread([this]() {
    int rc = netBase.loop();
    LOG_INFO("loop breaked: %d", rc);
  });
}

void NetStackSimple::stop() {
  if (!netThread) {
    LOG_ERR("Netstack is not running");
    return;
  }
  netBase.asyncBreakLoop();
  wait();
}

void NetStackSimple::wait() {
  if (netThread) {
    netThread->join();
    delete netThread;
    netThread = nullptr;
  }
}

void NetStackSimple::invoke(Task task) {
  netBase.dispatcher.invoke(task);
}

void NetStackSimple::beginInvoke(Task task) {
  netBase.dispatcher.beginInvoke(task);
}
