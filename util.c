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
#include "ipv4.h"

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

int get_device_info(char *device, u_char hwaddr[6], struct in_addr *uaddr,
                    struct in_addr *subnet, struct in_addr *mask) {
  struct ifreq ifreq;
  struct sockaddr_in addr;
  int soc;
  u_char *p;
  char buf[80];
  if ((soc = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
    debug_perror("socket");
    return -1;
  }
  memset(&ifreq, 0, sizeof(ifreq));
  strncpy(ifreq.ifr_name, device, sizeof(ifreq.ifr_name) - 1);

  if (ioctl(soc, SIOCGIFHWADDR, &ifreq) == -1) {
    debug_perror("ioctl");
    close(soc);
    return -1;
  } else {
    p = (u_char*)&ifreq.ifr_hwaddr.sa_data;
    memcpy(hwaddr, p, 6);
  }

  if (ioctl(soc, SIOCGIFADDR, &ifreq) == -1) {
    debug_perror("ioctl");
    close(soc);
    return -1;
  } else if (ifreq.ifr_addr.sa_family != PF_INET) {
    debug_printf("%s not PF_INET\n", device);
    close(soc);
    return -1;
  } else {
    memcpy(&addr, &ifreq.ifr_addr, sizeof(struct sockaddr_in));
    *uaddr = addr.sin_addr;
    //debug_printf("get device %s\n",in_addr_t2str(uaddr->s_addr,buf,sizeof(buf)));
  }

  if (ioctl(soc, SIOCGIFNETMASK, &ifreq) == -1) {
    debug_perror("ioctl");
    close(soc);
    return -1;
  } else {
    memcpy(&addr, &ifreq.ifr_addr, sizeof(struct sockaddr_in));
    *mask = addr.sin_addr;
  }
  subnet->s_addr = ((uaddr->s_addr) & (mask->s_addr));
  close(soc);
  return 0;

}

u_int16_t checksum(u_char *data, int len) {
  u_int32_t sum = 0;
  u_int16_t *ptr;
  int c;

  ptr = (u_int16_t *)data;
  for (c = len; c > 1; c -= 2) {
    sum += (*ptr);
    if (sum & 0x80000000) {
      sum = (sum & 0xffff) + (sum >> 16);
    }
    ptr++;
  }
  if (c == 1) {
    u_int16_t val = 0;
    memcpy(&val, ptr, sizeof(u_int8_t));
    sum += val;
  }

  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }
  return ~sum;
}

u_int16_t checksum2(u_char *data1, int len1, u_char *data2, int len2) {
  u_int32_t sum = 0;
  u_int16_t *ptr;
  int c;
  ptr = (u_int16_t *)data1;
  for (c = len1; c > 1; c -= 2) {
    sum += (*ptr);
    if (sum & 0x80000000) {
      sum = (sum & 0xffff) + (sum >> 16);
    }
    ptr++;
  }
  if (c == 1) {
    /* padding */
    u_int16_t val;
    val = ((*ptr) << 8) + (*data2);
    sum += val;
    if (sum & 0x80000000) {
      sum = (sum & 0xffff) + (sum >> 16);
    }
    ptr = (u_int16_t *)(data2 + 1);
    len2--;
  }
  else {
    ptr = (u_int16_t *)data2;
  }
  for (c = len2; c > 1; c -= 2) {
    sum += (*ptr);
    if (sum & 0x80000000) {
      sum = (sum & 0xffff) + (sum >> 16);
    }
    ptr++;
  }
  if (c == 1) {
    u_int16_t val = 0;
    memcpy(&val, ptr, sizeof(u_int8_t));
    sum += val;
  }
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }
  return ~sum;
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
