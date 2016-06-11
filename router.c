#include <stdio.h>
#include <poll.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <pthread.h>
#include <signal.h>
#include <config.h>
#include "ethernet.h"
#include "ipv4.h"
#include "icmp.h"
#include "util.h"

DEVICE device[DEVICE_NUM];

pthread_t buf_tid; //Packet submission thread
struct in_addr next_router;
const char *next_router_s = "192.168.0.1";
static int analyze_packet(int device_no, u_char *data, int size);
char *ether_ntoa(u_char *hwaddr, char *buf, socklen_t size);
int disable_ip_forward();
void *buffer_thread(void *arg);

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
  char buf[80];
  pthread_attr_t attr;
  char *in_dev, *out_dev;
  int status;

  if (argc != 3) {
    fprintf(stderr, "usage: vrouter <in_dev> <out_dev>\n");
    return 1;
  }
  in_dev = argv[1];
  out_dev = argv[2];
  inet_aton(next_router_s, &next_router_s);
  debug_printf("NextRouter=%s\n", _inet_ntoa_r(&next_router, buf, sizeof(buf)));

  if (get_device_info(in_dev, device[0].hwaddr, &device[0].addr,
                      &device[0].subnet, &device[0].netmask) == -1) {
    debug_printf("GetDeviceInfo:error:%s\n", in_dev);
    return -1;
  }
  if ((device[0].soc = init_raw_socket(in_dev, 1, 0)) == -1) {
    debug_printf("init_raw_socket:error:%s\n",in_dev);
    return -1;
  }
  if (get_device_info(in_dev, device[1].hwaddr, &device[1].addr,
                      &device[1].subnet, &device[1].netmask) == -1) {
    debug_printf("GetDeviceInfo:error:%s\n", out_dev);
    return -1;
  }
  if ((device[1].soc = init_raw_socket(out_dev, 1, 0)) == -1) {
    debug_printf("init_raw_socket:error:%s\n",out_dev);
    return -1;
  }

  disable_ip_forward();

  pthread_attr_init(&attr);
  if ((status = pthread_create(&buf_tid, &attr, buffer_thread, NULL)) != 0) {
    debug_printf("pthread_create:%s\n", strerror(status));
  }

  signal(SIGPIPE, SIG_IGN);
  signal(SIGTTIN, SIG_IGN);
  signal(SIGTTOU, SIG_IGN);

  debug_printf("router start\n");
  router();
  debug_printf("router end\n");

  close(device[0].soc);
  close(device[1].soc);

  return 0;
}

int disable_ip_forward() {
  FILE *fp;
  if ((fp = fopen("/proc/sys/net/ipv4/ip_forward", "w")) == NULL) {
    debug_printf("cannnot write /pro/sys/net/ipv4/ip_forward\n");
    return -1;
  }
  fputs("0", fp);
  fclose(fp);
  return 0;
}

void *buffer_thread(void *arg) {
  buffer_send();
  return NULL;
}

static int analyze_packet(int device_no, u_char *data, int size) {
  u_char *ptr;
  int lest;
  struct ether_header *eh;
  char buf[80];
  int tno;
  u_char hwaddr[6];

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
    //debug_printf("[%d]:dhost not match %s\n", device_no, ether_ntoa((u_char*)&eh->ether_dhost, buf, sizeof(buf)));
    return -1;
  }
  //debug_printf("[%d]:dhost match %s\n", device_no, ether_ntoa((u_char*)&eh->ether_dhost, buf, sizeof(buf)));
  #ifdef CONFIG_DEBUG
  print_ether_header(eh, stderr);
  #endif

  if (ntohs(eh->ether_type) == ETHERTYPE_ARP) {
    /* Recieved ARP type packet */
    struct ether_arp *arp;
    if (lest < sizeof(struct ether_arp)) {
      /* Packet size must be above or equal to ethernet header's. */
      debug_printf("[%d]:lest(%d)<sizeof(struct ether_header)\n", device_no, lest);
      return -1;
    }
    arp = (struct ether_arp *)ptr;
    ptr += sizeof(struct ether_arp);
    lest -= sizeof(struct ether_arp);

    if (arp->arp_op == htons(ARPOP_REQUEST)) {
      debug_printf("[%d]recv:ARP REQUEST:%dbytes\n",device_no, size);
      ip_2_mac(device_no, *(in_addr_t *)arp->arp_spa, arp->arp_sha);
    }
    if (arp->arp_op == htons(ARPOP_REPLY)) {
      debug_printf("[%d]recv:ARP REPLY:%dbytes\n",device_no, size);
      ip_2_mac(device_no, *(in_addr_t *)arp->arp_spa, arp->arp_sha);
    }
  }
  else if (ntohs(eh->ether_type) == ETHERTYPE_IP) {
    /* Recieved IP packet */
    struct iphdr *iphdr;
    u_char option[1500];
    int option_len;
    if (lest < sizeof(struct iphdr)) {
      /* Packet size must be above or equal to ethernet header's. */
      debug_printf("[%d]:lest(%d)<sizeof(struct iphdr)\n", device_no, lest);
      return -1;
    }
    iphdr = (struct iphdr *)ptr;
    ptr += sizeof(struct iphdr);
    lest -= sizeof(struct iphdr);

    option_len = iphdr->ihl * 4 - sizeof(struct iphdr);
    if (option_len > 0) {
      if (option_len >= 1500) {
        debug_printf("[%d]: IP option_len(%d): too big\n", device_no, option_len);
        return -1;
      }
      memcpy(option, ptr, option_len);
      ptr += option_len;
      lest -= option_len;
    }

    if (check_ip_checksum(iphdr, option, option_len) == 0) {
      debug_printf("[%d]: bad IP checksum\n",device_no);
      return -1;
    }
    if (iphdr->ttl - 1 == 0) {
      /* TTL have expired. Router must notice edge user it by ICMP. */
      debug_printf("[%d]: iphdr->ttl == 0 error\n",device_no);
      send_icmp_time_exceeded(device_no, eh, iphdr, data, size);
      return -1;
    }
    tno = get_opposite_dev(device_no);
    if ((iphdr->daddr & device[tno].netmask.s_addr) == device[tno].subnet.s_addr) {
      /* Same subnet network */
      IP2MAC *ip2mac;
      debug_printf("[%d]:%s to target segment\n", device_no, in_addr_t2str(iphdr->daddr, buf, sizeof(buf)));
      if (iphdr->daddr == device[tno].addr.s_addr) {
        debug_printf("[%d]:recv:myaddr\n",device_no);
        return 1;
      }
      ip2mac = ip_2_mac(tno, iphdr->daddr, NULL);
      if (ip2mac->flag == FLAG_NG || ip2mac->sd.dno != 0) {
        debug_printf("[%d]]Ip2Mac: error or sending\n", device_no);
        append_send_data(ip2mac, 1, iphdr->daddr, data, size);
        return -1;
      }
      else {
        memcpy(hwaddr, ip2mac->hwaddr, 6);
      }
    }
    else {
      IP2MAC *ip2mac;
      ip2mac = ip_2_mac(tno, next_router.s_addr, NULL);
      if (ip2mac->flag == FLAG_NG || ip2mac->sd.dno != 0) {
        debug_printf("[%d]:Ip2Mac: error or sending\n", device_no);
        append_send_data(ip2mac, 1, next_router.s_addr, data, size);
        return -1;
      }
      else {
        memcpy(hwaddr, ip2mac->hwaddr, 6);
      }
    }
    /* Finally we can send packet to next router. */
    memcpy(eh->ether_dhost, hwaddr, 6);
    memcpy(eh->ether_shost, device[tno].hwaddr, 6);

    iphdr->ttl--;
    iphdr->check = 0;
    iphdr->check = checksum2((u_char *)iphdr, sizeof(struct iphdr), option, option_len);
    write(device[tno].soc, data, size);
  }
  return 0;
}
