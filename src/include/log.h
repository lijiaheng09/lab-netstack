#ifndef NETSTACK_LOG_H
#define NETSTACK_LOG_H

#include <cstdio>
#include <cassert>

#ifdef NETSTACK_DEBUG

#define ERRLOG(...) fprintf(stderr, __VA_ARGS__)

#define LOG_INFO(msg, ...) fprintf(stderr, msg "\n", ##__VA_ARGS__)
#define LOG_ERR(msg, ...) fprintf(stderr, msg "\n", ##__VA_ARGS__)
#define LOG_ERR_POSIX(msg, ...) fprintf(stderr, msg ": %s\n", ##__VA_ARGS__, strerror(errno))
#define LOG_ERR_PCAP(p, msg, ...) fprintf(stderr, msg ": %s\n", ##__VA_ARGS__, pcap_geterr(p))
#define NS_ASSERT(...) assert(__VA_ARGS__)

#else

#define ERRLOG(...)

#define LOG_INFO(...)
#define LOG_ERR(...)
#define LOG_ERR_POSIX(...)
#define LOG_ERR_PCAP(...)
#define NS_ASSERT(...)

#endif

#endif
