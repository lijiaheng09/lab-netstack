#ifndef TOOLS_UTILS_H
#define TOOLS_UTILS_H

#include "nsInstance.h"

Ethernet::Device *findDeviceByName(const char *name);

template <typename TFunc> void invoke(TFunc f) {
  ns.invoke(f);
}

#define INVOKE(body) invoke([&]() body);

#endif
