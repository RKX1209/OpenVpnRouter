#ifndef __ARP_H
#define __ARP_H

#include <netinet/if_ether.h>
#include <net/ethernet.h>

typedef struct {
  struct ether_header eh;
  struct ether_arp arp;
}PACKET_ARP;

#endif
