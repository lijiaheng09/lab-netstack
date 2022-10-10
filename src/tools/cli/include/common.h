#ifndef TOOLS_UTILS_H
#define TOOLS_UTILS_H

#include "netstack.h"

Ethernet::Device *findDeviceByName(const char *name);

template <typename TFunc> void invoke(TFunc f) {
  auto task = LoopCallback::wrap([f]() -> int {
    f();
    return 0;
  });
  loopDispatcher.invoke(&task);
}

#define INVOKE(body) invoke([&]() body);

#endif
