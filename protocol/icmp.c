#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include "util.h"
#include "icmp.h"

extern DEVICE device[DEVICE_NUM];

int send_icmp_time_exceeded(int device_no, struct ether_header *eh,
                          struct iphdr *iphdr, u_char *data, int size) {
  struct ether_header reh;
  struct iphdr rih;
  struct icmp icmp;
  u_char *ipptr;
  u_char *ptr, buf[1500];
  int len;

  memcpy(reh.ether_dhost, eh->ether_dhost, 6);
  memcpy(reh.ether_shost, device[device_no].hwaddr, 6);
  reh.ether_type = htons(ETHERTYPE_IP);

  rih.version = 4;
  rih.ihl = 20 / 4;
  rih.tos = 0;
  rih.tot_len = htons(sizeof(struct icmp) + 64);
  rih.id = 0;
  rih.frag_off = 0;
  rih.ttl = 64;
  rih.protocol = IPPROTO_ICMP;
  rih.check = 0;
  rih.saddr = device[device_no].addr.s_addr;
  rih.daddr = iphdr->saddr;

  rih.check = checksum((u_char *)&rih, sizeof(struct iphdr))    ;

  icmp.icmp_type = ICMP_TIME_EXCEEDED;
  icmp.icmp_code = ICMP_TIMXCEED_INTRANS;
  icmp.icmp_cksum = 0;
  icmp.icmp_void = 0;

  ipptr = data + sizeof(struct ether_header);

  icmp.icmp_cksum = checksum2((u_char *)&icmp, 8, ipptr, 64);

  ptr = buf;
  memcpy(ptr, &reh, sizeof(struct ether_header));
  ptr += sizeof(struct ether_header);
  memcpy(ptr, &rih, sizeof(struct iphdr));
  ptr += sizeof(struct iphdr);
  memcpy(ptr, &icmp, 8);
  ptr += 8;
  memcpy(ptr, ipptr, 64);
  ptr += 64;
  len = ptr - buf;
  write(device[device_no].soc, buf, len);
  return 0;
}
