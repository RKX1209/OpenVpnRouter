#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>

char *inet_ntoa(struct in_addr *addr, char *buf, socklen_t size) {
  inet_ntop(PF_INET, addr, buf, size);
  return buf;
}

char *inet_ntoa_t(struct in_addr_t *addr, char *buf, socklen_t size) {
  struct in_addr ia;
  ia.s_addr = addr;
  inet_ntop(PF_INET, &ia, buf, size);
  return buf;
}
