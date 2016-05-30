#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <config.h>
#include "util.h"

int init_raw_socket(char *device, int promisc, int ip_only) {
  struct ifreq ifreq;
  struct sockaddr_ll sa;
  int soc;

  if (ip_only) {
    if ((soc = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0) {
      debug_perror("socket");
      return -1;
    }
  } else {
    if ((soc = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
      debug_perror("socket");
      return -1;
    }
  }

  memset(&ifreq, 0, sizeof(struct ifreq));
  strncpy(ifreq.ifr_name, device, sizeof(ifreq.ifr_name) - 1);
  if (ioctl(soc, SIOCGIFINDEX, &ifreq) < 0) {
    perror("ioctl");
    close(soc);
    return -1;
  }

  sa.sll_family = PF_PACKET;
  if (ip_only) {
    sa.sll_protocol = htons(ETH_P_IP);
  } else {
    sa.sll_protocol = htons(ETH_P_ALL);
  }
  sa.sll_ifindex = ifreq.ifr_ifindex;
  if (bind(soc, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
    perror("bind");
    close(soc);
    return -1;
  }

  if (promisc) {
    if (ioctl(soc, SIOCGIFFLAGS, &ifreq) < 0) {
      perror("ioctl");
      close(soc);
      return -1;
    }
    ifreq.ifr_flags = ifreq.ifr_flags | IFF_PROMISC;
    if (ioctl(soc, SIOCGIFFLAGS, &ifreq) < 0) {
      perror("ioctl");
      close(soc);
      return -1;
    }
  }
  return soc;
}

int debug_printf(char *fmt, ...) {
  #ifdef CONFIG_DEBUG
  va_list args;
  va_start(args, fmt);
  vfprintf(stderr, fmt, args);
  va_end(args);
  #endif
  return 0;
}

int debug_perror(char *msg) {
  #ifdef CONFIG_DEBUG
  fprintf(stderr, "%s: %s\n", msg, strerror(errno));
  #endif
  return 0;
}
