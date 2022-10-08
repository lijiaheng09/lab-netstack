#ifndef NETSTACK_LOG_H
#define NETSTACK_LOG_H

#include <cstdio>

#ifdef NETSTACK_DEBUG
#define ERRLOG(...) fprintf(stderr, __VA_ARGS__)
#else
#define ERRLOG(...)
#endif

#endif
