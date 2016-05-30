#include <stdio.h>
#include <poll.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <pthread.h>
#include "util.h"
#include "ethernet.h"
#include "ipv4.h"

#define DEVICE_NUM 2
#define get_opposite_dev(x) (!x)

typedef struct {
  int soc;
  u_char hwaddr[6];
}DEVICE;
DEVICE device[DEVICE_NUM];

static int analyze_packet(int device_no, u_char *data, int size);
char *ether_ntoa(u_char *hwaddr, char *buf, socklen_t size);

int router() {
  struct pollfd targets[DEVICE_NUM];
  int i;
  int status,size;
  u_char buf[2048];

  targets[0].fd = device[0].soc;
  targets[0].events = POLLIN | POLLERR;
  targets[1].fd = device[1].soc;
  targets[1].events = POLLIN | POLLERR;

  while(1) {
    switch(status = poll(targets, DEVICE_NUM, 100)) {
      case -1:
        if (errno != EINTR) {
          perror("poll");
        }
        break;
      case 0:
        break;
      default:
        for(i = 0; i < DEVICE_NUM; i++) {
          if (targets[i].revents & (POLLIN|POLLERR)) {
            if ((size = read(device[i].soc, buf, sizeof(buf))) <= 0) {
              perror("cannnot read device");
            } else {
              if (analyze_packet(i, buf, size) != -1) {
                if ((size = write(device[get_opposite_dev(i)].soc, buf, size)) <= 0) {
                  perror("cannnot write device");
                }
              }
            }
          }
        }
        break;
    }
  }
}

int main(int argc, char *argv[]) {
  char *in_dev, *out_dev;
  if (argc != 2) {
    fprintf(stderr, "usage: vrouter <in_dev> <out_dev>");
    return 1;
  }
  in_dev = argv[1];
  out_dev = argv[2];
  if ((device[0].soc = init_raw_socket(in_dev, 1, 0)) == -1) {
    debug_printf("init_raw_socket:error:%s\n",in_dev);
    return -1;
  }
  if ((device[1].soc = init_raw_socket(out_dev, 1, 0)) == -1) {
    debug_printf("init_raw_socket:error:%s\n",out_dev);
    return -1;
  }

}

static int analyze_packet(int device_no, u_char *data, int size) {
  u_char *ptr;
  int lest;
  struct ether_header *eh;
  char buf[80];
  ptr = data;
  lest = size;
  if (lest < sizeof(struct ether_header)) {
    /* Packet size must be above or equal to ethernet header's. */
    debug_printf("[%d]:lest(%d)<sizeof(struct ether_header)\n", device_no, lest);
    return -1;
  }
  eh = (struct ether_header *)ptr;
  ptr += sizeof(struct ether_header);
  lest -= sizeof(struct ether_header);
  if (memcmp(&eh->ether_dhost, device[device_no].hwaddr, 6) != 0) {
    debug_printf("[%d]:dhost not match %s\n", device_no, ether_ntoa((u_char*)&eh->ether_dhost, buf, sizeof(buf)));
    return -1;
  }
  #ifdef CONFIG_DEBUG
  print_ether_header(eh, stderr);
  #endif
  return 0;
}
