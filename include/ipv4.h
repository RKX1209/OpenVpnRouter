#ifndef __IPV4_H
#define __IPV4_H

#include <netinet/ip.h>

char *_inet_ntoa(struct in_addr *addr, char *buf, socklen_t size);
char *_inet_ntoa_r(struct in_addr *addr, char *buf, socklen_t size);
char *in_addr_t2str(in_addr_t addr, char *buf, socklen_t size);
int check_ip_checksum(struct iphdr *iphdr, u_char *option, int option_len);
#endif
