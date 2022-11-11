#include <cstring>
#include <cstdlib>

#include "commands.h"

Command::Command(const char *name_) : name(strdup(name_)) {}

Command::~Command() {
  free(name);
}

#include "commands/Devices.hpp"
#include "commands/Control.hpp"
#include "commands/FrameIO.hpp"

#include "commands/EthTest.hpp"

#include "commands/PacketIO.hpp"
#include "commands/IPConfig.hpp"

#include "commands/IPForward.hpp"

#include "commands/UdpIO.hpp"

#include "commands/AutoConfig.hpp"
#include "commands/IPUtils.hpp"

#include "commands/TCPTest.hpp"

std::vector<Command *> allCommands = {
  new CmdAddDevice(),
  new CmdFindDevice(),
  new CmdStartLoop(),

  new CmdSendFrame(),
  new CmdCaptureFrames(),
  new CmdCapturePackets(),

  new CmdEthTest(),

  new CmdIPAddrAdd(),
  new CmdArpInfo(),
  new CmdRouteAdd(),
  new CmdRouteRip(),
  new CmdRouteInfo(),
  new CmdRouteRipInfo(),

  new CmdIPForward(),

  new CmdNcUdpListen(),
  new CmdNcUdp(),

  new CmdAutoConfig(),
  new CmdPing(),
  new CmdTraceRoute(),

  new CmdTcpTest(),

  new CmdSleep()
};
