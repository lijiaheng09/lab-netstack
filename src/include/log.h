#ifndef NETSTACK_LOG_H
#define NETSTACK_LOG_H

#include <cstdio>

#ifdef NETSTACK_DEBUG
#define ERRLOG(...) fprintf(stderr, __VA_ARGS__)

#define LOG_ERR(msg, ...) fprintf(stderr, msg "\n", ##__VA_ARGS__)
#define LOG_ERR_POSIX(msg, ...) fprintf(stderr, msg ": %s\n", ##__VA_ARGS__, strerror(errno))
#define LOG_ERR_PCAP(p, msg, ...) fprintf(stderr, msg ": %s\n", ##__VA_ARGS__, pcap_geterr(p))
#else
#define ERRLOG(...)

#define LOG_ERR(...)
#define LOG_ERR_POSIX(...)
#define LOG_ERR_PCAP(...)
#endif

#endif
