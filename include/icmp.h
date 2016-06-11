#ifndef __ICMP_H
#define __ICMP_H
#include <netinet/ip_icmp.h>

int send_icmp_time_exceeded(int device_no, struct ether_header *eh,
                            struct iphdr *iphdr, u_char *data, int size);
#endif
