#include "socket.h"
#include "NetStackFull.h"

#include <climits>

#include "log.h"

class AutoNetStack : public NetStackFull {
public:
  AutoNetStack();
  ~AutoNetStack();
};

static AutoNetStack ns;

static int curFd = 65536;
static HashMap<int, TCP::Desc *> fds;

AutoNetStack::AutoNetStack() : NetStackFull() {
  if (autoConfig(false) != 0 || configRIP() != 0 || enableForward() != 0) {
    LOG_ERR("netstack init error");
    abort();
  }
  start();
}

AutoNetStack::~AutoNetStack() {
  for (auto &&e : fds) {
    // abort
  }
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
  if (curFd == INT_MAX) {
    errno = ENFILE;
    return -1;
  }

  LOG_INFO("Using lab-netstack socket");

  TCP::Desc *desc = ns.tcp.create();
  if (!desc) {
    return -1;
  }
  int fd = curFd++;
  fds[fd] = desc;
  return fd;
}

int __wrap_bind(int fd, const struct sockaddr *address, socklen_t address_len) {
  if (!fds.count(fd))
    return __real_bind(fd, address, address_len);

  if (address_len != sizeof(sockaddr_in) && address->sa_family != AF_INET) {
    errno = EAFNOSUPPORT;
    return -1;
  }

  auto *addr_in = (const struct sockaddr_in *)address;
  TCP::Sock sock;
  memcpy(&sock.addr, &addr_in->sin_addr, sizeof(IP::Addr));
  sock.port = ntohs(addr_in->sin_port);

  TCP::Desc *d = fds[fd];
  int rc;
  ns.invoke([&rc, d, sock]() { rc = d->bind(sock); });
  if (rc != 0)
    return -1;
  return 0;
}

int __wrap_listen(int fd, int backlog) {
  if (!fds.count(fd))
    return __real_listen(fd, backlog);

  TCP::Desc *d = fds[fd];
  TCP::Listener *r;
  ns.invoke([&r, d]() { r = ns.tcp.listen(d); });
  if (!r)
    return -1;
  fds[fd] = r;
  return 0;
}

int __wrap_connect(int fd, const struct sockaddr *address,
                   socklen_t address_len) {
  if (!fds.count(fd))
    return __real_connect(fd, address, address_len);

  if (address_len != sizeof(sockaddr_in) && address->sa_family != AF_INET) {
    errno = EAFNOSUPPORT;
    return -1;
  }

  auto *addr_in = (const struct sockaddr_in *)address;
  TCP::Sock sock;
  memcpy(&sock.addr, &addr_in->sin_addr, sizeof(sock.addr));
  sock.port = ntohs(addr_in->sin_port);

  TCP::Desc *d = fds[fd];
  TCP::Connection *r;
  ns.invoke([&r, d, sock]() { r = ns.tcp.connect(d, sock); });
  if (!r)
    return -1;
  fds[fd] = r;
  return 0;
}

int __wrap_accept(int fd, struct sockaddr *address, socklen_t *address_len) {
  if (!fds.count(fd))
    return __real_accept(fd, address, address_len);

  TCP::Listener *d = dynamic_cast<TCP::Listener *>(fds[fd]);
  if (!d) {
    errno = EINVAL;
    return -1;
  }
  if (curFd == INT_MAX) {
    errno = ENFILE;
    return -1;
  }
  TCP::Connection *c = d->awaitAccept();
  if (!c)
    return -1;
  int accFd = curFd++;
  fds[accFd] = c;

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
  if (!fds.count(fd))
    return __real_read(fd, buf, nbyte);

  TCP::Connection *d = dynamic_cast<TCP::Connection *>(fds[fd]);
  if (!d) {
    errno = EINVAL;
    return -1;
  }

  ssize_t rc = d->awaitRecv(buf, nbyte);
  if (rc < 0)
    return -1;
  return rc;
}

ssize_t __wrap_write(int fd, const void *buf, size_t nbyte) {
  if (!fds.count(fd))
    return __real_write(fd, buf, nbyte);

  TCP::Connection *d = dynamic_cast<TCP::Connection *>(fds[fd]);
  if (!d) {
    errno = EINVAL;
    return -1;
  }

  ssize_t rc = d->asyncSend(buf, nbyte);
  if (rc < 0)
    return -1;
  return rc;
}

int __wrap_close(int fd) {
  if (!fds.count(fd))
    return __real_close(fd);

  TCP::Desc *d = fds[fd];
  int rc = d->awaitClose();
  fds.erase(fd);
  if (rc < 0)
    return -1;
  return 0;
}

int __wrap_getaddrinfo(const char *node, const char *service,
                       const struct addrinfo *hints, struct addrinfo **res) {
  return __real_getaddrinfo(node, service, hints, res);
}
