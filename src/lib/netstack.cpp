#include <pcap/pcap.h>

#include "netstack.h"

int netstackInit() {
  char errbuf[PCAP_ERRBUF_SIZE];
  if (pcap_init(PCAP_CHAR_ENC_UTF_8, errbuf) != 0)
    return -1;
  return 0;
}
