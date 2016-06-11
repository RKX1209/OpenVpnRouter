#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <time.h>
#include <string.h>
#include "arp.h"

int send_arp_requestb(int soc, in_addr_t target_ip, u_char target_mac[6],
                      in_addr_t my_ip, u_char my_mac[6]) {
  PACKET_ARP arp;
  int total;
  u_char *p;
  u_char buf[sizeof(struct ether_header) + sizeof(struct ether_arp)];
  union {
    unsigned long l;
    u_char c[4];
  }lc;
  int i;
  arp.arp.arp_hrd = htons(ARPHRD_ETHER);
  arp.arp.arp_pro = htons(ETHERTYPE_IP);
  arp.arp.arp_hln = 6;
  arp.arp.arp_pln = 4;
  arp.arp.arp_op = htons(ARPOP_REQUEST);
  for (i = 0; i < 6; i++) {
    arp.arp.arp_sha[i] = my_mac[i];
    arp.arp.arp_tha[i] = 0;
  }
  lc.l = my_ip;
  for (i = 0; i < 4; i++) {
    arp.arp.arp_spa[i] = lc.c[i];
  }

  arp.eh.ether_dhost[0] = target_mac[0];
  arp.eh.ether_dhost[1] = target_mac[1];
  arp.eh.ether_dhost[2] = target_mac[2];
  arp.eh.ether_dhost[3] = target_mac[3];
  arp.eh.ether_dhost[4] = target_mac[4];
  arp.eh.ether_dhost[5] = target_mac[5];

  arp.eh.ether_shost[0] = my_mac[0];
  arp.eh.ether_shost[1] = my_mac[1];
  arp.eh.ether_shost[2] = my_mac[2];
  arp.eh.ether_shost[3] = my_mac[3];
  arp.eh.ether_shost[4] = my_mac[4];
  arp.eh.ether_shost[5] = my_mac[5];

  arp.eh.ether_type = htons(ETHERTYPE_ARP);
  memset(buf, 0, sizeof(buf));
  total = p - buf;
  write(soc, buf, total);
  return 0;
}
