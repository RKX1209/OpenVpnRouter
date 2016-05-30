#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>

char *ether_ntoa(u_char *hwaddr, char *buf, socklen_t size) {
  snprintf(buf, size, "%02x:%02x:%02x:%02x:%02x:%02x",
          hwaddr[0],hwaddr[1],hwaddr[2],
          hwaddr[3],hwaddr[4],hwaddr[5]);
  return buf;
}

int print_ether_header(struct ether_header *eh, FILE *fp) {
  char buf[128];
  fprintf(fp, "ether_header################\n");
  fprintf(fp, "ether_dhost=%s\n", ether_ntoa(eh->ether_dhost, buf, sizeof(buf)));
  fprintf(fp, "ether_shost=%s\n", ether_ntoa(eh->ether_shost, buf, sizeof(buf)));
  fprintf(fp, "ether_type=%02x\n", ntohs(eh->ether_type));
  switch(ntohs(eh->ether_type)) {
    case ETH_P_IP:
      fprintf(fp, "(IP)\n");
      break;
    case ETH_P_IPV6:
      fprintf(fp, "(IPv6)\n");
      break;
    case ETH_P_ARP:
      fprintf(fp, "(ARP)\n");
      break;
    default:
      fprintf(fp, "(unknown)\n");
      break;
  }
  return 0;
}
