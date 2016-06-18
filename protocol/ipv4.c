#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include "ipv4.h"
#include "util.h"

char *_inet_ntoa_r(struct in_addr *addr, char *buf, socklen_t size) {
  inet_ntop(PF_INET, addr, buf, size);
  return buf;
}

char *in_addr_t2str(in_addr_t addr, char *buf, socklen_t size) {
  struct in_addr a;
  a.s_addr = addr;
  inet_ntop(PF_INET, &a, buf, size);
  return buf;
}

int check_ip_checksum(struct iphdr *iphdr, u_char *option, int option_len) {
  struct iphdr iptmp;
  unsigned short sum;
  memcpy(&iptmp, iphdr, sizeof(struct iphdr));
  if (option_len == 0) {
    sum = checksum((u_char *)&iptmp, sizeof(struct iphdr));
    if (sum == 0 || sum == 0xffff) {
      return 1;
    }
    else {
      return 0;
    }
  }
  else {
    sum = checksum2((u_char *)&iptmp, sizeof(struct iphdr), option, option_len);
    if (sum == 0 || sum == 0xffff) {
      return 1;
    }
    else {
      return 0;
    }
  }
}
