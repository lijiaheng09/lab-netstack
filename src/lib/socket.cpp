#include "socket.h"
#include "NetStackFull.h"

#include <climits>
#include <shared_mutex>
#include <mutex>

#include "log.h"

class AutoNetStack : public NetStackFull {
  int curFd;
  std::mutex mutCFd;
  std::shared_mutex mutFds;
  HashMap<int, TCP::Desc *> fds;

public:
  AutoNetStack();
  ~AutoNetStack();

  int nextFd() {
    std::unique_lock lk(mutCFd);
    return curFd++;
  }

  TCP::Desc *getFd(int fd) {
    std::shared_lock lk(mutFds);
    auto it = fds.find(fd);
    if (it == fds.end())
      return nullptr;
    return it->second;
  }

  void setFd(int fd, TCP::Desc *d) {
    std::unique_lock lk(mutFds);
    fds[fd] = d;
  }

  void eraseFd(int fd) {
    std::unique_lock lk(mutFds);
    fds.erase(fd);
  }
};

static AutoNetStack ns;

AutoNetStack::AutoNetStack() : NetStackFull(), curFd(65536) {
  if (autoConfig(true) != 0) {
    LOG_ERR("netstack init error");
    abort();
  }

  // To talk with other real systems, manually config the routing table
  // In kernel netstack, this should be read from the system config...
  auto &&addrs = ip.getAddrs();
  if (addrs.size() == 1) {
    auto *r = dynamic_cast<LpmRouting *>(ip.getRouting());
    IP::Addr gw = addrs.front().addr;

    // *.*.*.1 <---> *.*.*.2
    gw.data[3] = ((gw.data[3] - 1) ^ 1) + 1;

    r->setEntry({.addr{0, 0, 0, 0},
                 .mask{0, 0, 0, 0},
                 .device = addrs.front().device,
                 .gateway = gw});
  }

  start();
}

AutoNetStack::~AutoNetStack() {
  for (auto &&e : fds)
    e.second->awaitClose();
}

int __wrap_socket(int domain, int type, int protocol) {
  if (domain != AF_INET) {
    errno = EAFNOSUPPORT;
    return -1;
  }
  if (type != SOCK_STREAM) {
    errno = EPROTOTYPE;
    return -1;
  }
  if (protocol != 0) {
    errno = EPROTONOSUPPORT;
    return -1;
  }

  LOG_INFO("Using lab-netstack socket");

  int fd = ns.nextFd();
  if (fd < 0) {
    errno = ENFILE;
    return -1;
  }
  TCP::Desc *desc = ns.tcp.create();
  if (!desc) {
    // impossible
    return -1;
  }
  ns.setFd(fd, desc);
  return fd;
}

int __wrap_bind(int fd, const struct sockaddr *address, socklen_t address_len) {
  auto *d = ns.getFd(fd);
  if (!d)
    return __real_bind(fd, address, address_len);

  if (address_len != sizeof(sockaddr_in) && address->sa_family != AF_INET) {
    errno = EAFNOSUPPORT;
    return -1;
  }

  auto *addr_in = (const struct sockaddr_in *)address;
  TCP::Sock sock;
  memcpy(&sock.addr, &addr_in->sin_addr, sizeof(IP::Addr));
  sock.port = ntohs(addr_in->sin_port);

  int rc;
  ns.invoke([&rc, d, sock]() { rc = d->bind(sock); });
  if (rc != 0) {
    errno = EADDRINUSE;
    return -1;
  }
  return 0;
}

int __wrap_listen(int fd, int backlog) {
  auto *d = ns.getFd(fd);
  if (!d)
    return __real_listen(fd, backlog);

  TCP::Listener *r;
  ns.invoke([&r, d]() { r = ns.tcp.listen(d); });
  if (!r) {
    errno = EINVAL;
    return -1;
  }
  ns.setFd(fd, r);
  return 0;
}

int __wrap_connect(int fd, const struct sockaddr *address,
                   socklen_t address_len) {
  auto *d = ns.getFd(fd);
  if (!d)
    return __real_connect(fd, address, address_len);

  if (address_len != sizeof(sockaddr_in) && address->sa_family != AF_INET) {
    errno = EAFNOSUPPORT;
    return -1;
  }

  auto *addr_in = (const struct sockaddr_in *)address;
  TCP::Sock sock;
  memcpy(&sock.addr, &addr_in->sin_addr, sizeof(sock.addr));
  sock.port = ntohs(addr_in->sin_port);

  TCP::Connection *r;
  ns.invoke([&r, d, sock]() { r = ns.tcp.connect(d, sock); });
  if (!r) {
    errno = ENETUNREACH;
    return -1;
  }
  ns.setFd(fd, r);
  return 0;
}

int __wrap_accept(int fd, struct sockaddr *address, socklen_t *address_len) {
  auto *d = ns.getFd(fd);
  if (!d)
    return __real_accept(fd, address, address_len);

  TCP::Listener *l = dynamic_cast<TCP::Listener *>(d);
  if (!d) {
    errno = EINVAL;
    return -1;
  }
  int accFd = ns.nextFd();
  if (accFd < 0) {
    errno = ENFILE;
    return -1;
  }
  TCP::Connection *c = l->awaitAccept();
  if (!c) {
    errno = ECONNABORTED;
    return -1;
  }
  ns.setFd(accFd, c);

  if (address) {
    sockaddr_in addr_in{.sin_family = AF_INET,
                        .sin_port = htons(c->foreign.port)};
    memcpy(&addr_in.sin_addr, &c->foreign.addr, sizeof(IP::Addr));
    memcpy(address, &addr_in, std::min(sizeof(addr_in), (size_t)*address_len));
    *address_len = sizeof(addr_in);
  }
  return accFd;
}

ssize_t __wrap_read(int fd, void *buf, size_t nbyte) {
  auto *d = ns.getFd(fd);
  if (!d)
    return __real_read(fd, buf, nbyte);

  TCP::Connection *c = dynamic_cast<TCP::Connection *>(d);
  if (!d) {
    errno = EINVAL;
    return -1;
  }

  ssize_t rc = c->awaitRecv(buf, nbyte);
  if (rc < 0) {
    errno = ECONNABORTED;
    return -1;
  }
  return rc;
}

ssize_t __wrap_write(int fd, const void *buf, size_t nbyte) {
  auto *d = ns.getFd(fd);
  if (!d)
    return __real_write(fd, buf, nbyte);

  TCP::Connection *c = dynamic_cast<TCP::Connection *>(d);
  if (!d) {
    errno = EINVAL;
    return -1;
  }

  ssize_t rc = c->asyncSend(buf, nbyte);
  if (rc < 0) {
    errno = ECONNABORTED;
    return -1;
  }
  return rc;
}

int __wrap_close(int fd) {
  auto *d = ns.getFd(fd);
  if (!d)
    return __real_close(fd);

  int rc = d->awaitClose();
  ns.eraseFd(fd);
  if (rc < 0) {
    // impossible
    return -1;
  }
  return 0;
}

int __wrap_getaddrinfo(const char *node, const char *service,
                       const struct addrinfo *hints, struct addrinfo **res) {
  IP::Addr addr{0};
  uint16_t port = 0;
  if (hints) {
    if (hints->ai_family != AF_INET) {
      return EAI_FAMILY;
    }
    if (hints->ai_socktype != IPPROTO_TCP) {
      return EAI_SOCKTYPE;
    }
    if (hints->ai_flags != 0) {
      return EAI_BADFLAGS;
    }
  }
  if (node) {
    if (sscanf(node, IP_ADDR_FMT_STRING, IP_ADDR_FMT_ARGS(&addr)) !=
        IP_ADDR_FMT_NUM) {
      return EAI_NONAME;
    }
  }
  if (service) {
    if (sscanf(service, "%hu", &port) != 1) {
      return EAI_SERVICE;
    }
  }

  auto *saddr = new sockaddr_in{.sin_family = AF_INET, .sin_port = htons(port)};
  memcpy(&saddr->sin_addr, &addr, sizeof(IP::Addr));

  *res = new addrinfo{.ai_flags = 0,
                      .ai_family = AF_INET,
                      .ai_socktype = SOCK_DGRAM,
                      .ai_protocol = 0,
                      .ai_addrlen = sizeof(sockaddr_in),
                      .ai_addr = (struct sockaddr *)saddr};
  return 0;
}

void __wrap_freeaddrinfo(struct addrinfo *ai) {
  struct addrinfo *nxt = nullptr;
  for (auto *p = ai; p; p = nxt) {
    nxt = p->ai_next;
    if (p->ai_addr)
      delete p->ai_addr;
    delete p;
  }
}

int __wrap_setsockopt(int fd, int level, int option_name,
                      const void *option_value, socklen_t option_len) {
  if (!ns.getFd(fd))
    return __real_setsockopt(fd, level, option_name, option_value, option_len);
  errno = ENOPROTOOPT;
  return -1;
}
