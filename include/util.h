#ifndef __UTIL_H
#define __UTIL_H

#define DEVICE_NUM 2
#define get_opposite_dev(x) (!x)

typedef struct {
  int soc;
  u_char hwaddr[6];
  struct in_addr addr, subnet, netmask;
}DEVICE;

int init_raw_socket(char *device, int promisc, int ip_only);
int get_device_info(char *device, u_char hwaddr[6], struct in_addr *uaddr,
                    struct in_addr *subnet, struct in_addr *mask);
u_int16_t checksum(u_char *data, int len);
u_int16_t checksum2(u_char *data1, int len1, u_char *data2, int len2);
int debug_printf(char *fmt, ...);
int debug_perror(char *msg);

#endif
