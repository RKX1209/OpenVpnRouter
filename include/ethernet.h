#ifndef __ETHERNET_H
#define __ETHERNET_H

#include <netinet/if_ether.h>
#include <netinet/in.h>
#include "util.h"

#define IP2MAC_TIMEOUT_SEC  60
#define IP2MAC_NG_TIMEOUT_SEC 1
#define MAX_BUCKET_SIZE 1024
#define FLAG_FREE 0
#define FLAG_OK   1
#define FLAG_NG   -1

extern DEVICE device[DEVICE_NUM];

typedef struct _data_buf_ {
  struct _data_buf_ *next;
  struct _data_buf_ *before;
  time_t t;
  int size;
  unsigned char *data;
} DATA_BUF;

typedef struct {
  DATA_BUF *top;
  DATA_BUF *bottom;
  unsigned long dno;
  unsigned int in_bucket_size;
  pthread_mutex_t mutex;
}SEND_DATA;

typedef struct {
  int flag;
  int device_no;
  u_char *hwaddr[6];
  in_addr_t addr;
  time_t last_time;
  SEND_DATA sd;
}IP2MAC;

typedef struct _send_req_data_ {
  struct _send_req_data_ *next;
  struct _send_req_data_ *before;
  int device_no;
  int ip2mac_no;
}SEND_REQ_DATA;

struct _ip_2_macs{
  IP2MAC *data;
  int size;
  int no;
};
extern struct _ip_2_macs ip_2_macs[2];

struct _send_req {
  SEND_REQ_DATA *top;
  SEND_REQ_DATA *bottom;
  pthread_mutex_t mutex;
  pthread_cond_t cond;
};
extern struct _send_req send_req;

int append_send_req_data(int device_no, int ip2mac_no);
int append_send_data(IP2MAC *ip2mac, int device_no, in_addr_t addr, u_char *data, int size);
int get_send_data(IP2MAC *ip2mac, int *size, u_char **data);
int free_send_data(IP2MAC *ip2mac);
int buffer_send();
int buffer_send_one(int device_no, IP2MAC *ip2mac);
int get_send_req_data(int *device_no, int *ip2mac_no);
IP2MAC *ip_2_mac(int device_no, in_addr_t addr, u_char *hwaddr);
char *ether_ntoa(u_char *hwaddr, char *buf, socklen_t size);
int print_ether_header(struct ether_header *eh, FILE *fp);

#endif
