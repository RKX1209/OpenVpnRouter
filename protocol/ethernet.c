#include <stdio.h>
#include <time.h>
#include <string.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdlib.h>
#include "ethernet.h"
#include "ipv4.h"

struct _ip_2_macs ip_2_macs[2];
struct _send_req send_req = {NULL, NULL, PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER};

char *ether_ntoa(u_char *hwaddr, char *buf, socklen_t size) {
  snprintf(buf, size, "%02x:%02x:%02x:%02x:%02x:%02x",
          hwaddr[0],hwaddr[1],hwaddr[2],
          hwaddr[3],hwaddr[4],hwaddr[5]);
  return buf;
}

IP2MAC *ip_2_mac_search(int device_no, in_addr_t addr, u_char *hwaddr) {
  int i;
  int free_no,no;
  time_t now;
  char buf[80];
  IP2MAC *ip2mac;

  free_no = -1;
  now = time(NULL);
  for (i = 0; i < ip_2_macs[device_no].no; i++) {
    ip2mac = &ip_2_macs[device_no].data[i];
    if (ip2mac->flag == FLAG_FREE) {
      if (free_no == -1) {
        free_no = i;
      }
      continue;
    }
    if (ip2mac->addr == addr) {
      if (ip2mac->flag == FLAG_OK) {
        ip2mac->last_time = now;
      }
      if (hwaddr != NULL) {
        memcpy(ip2mac->hwaddr, hwaddr, 6);
        ip2mac->flag = FLAG_OK;
        if (ip2mac->sd.top != NULL) {
          append_send_req_data(device_no, i);
        }
        return ip2mac;
      }
      else {
        if ((ip2mac->flag == FLAG_OK && now - ip2mac->last_time > IP2MAC_TIMEOUT_SEC) ||
            (ip2mac->flag == FLAG_NG && now - ip2mac->last_time > IP2MAC_NG_TIMEOUT_SEC)) {
              /* time has expired */
              free_send_data(ip2mac);
              ip2mac->flag = FLAG_FREE;
              if (free_no == -1) {
                free_no = i;
              }
            }
        else {
          return ip2mac;
        }
      }
    }
    else {
        if ((ip2mac->flag == FLAG_OK && now - ip2mac->last_time > IP2MAC_TIMEOUT_SEC) ||
            (ip2mac->flag == FLAG_NG && now - ip2mac->last_time > IP2MAC_NG_TIMEOUT_SEC)) {
              /* time has expired */
              free_send_data(ip2mac);
              ip2mac->flag = FLAG_FREE;
              if (free_no == -1) {
                free_no = i;
              }
            }
    }
  }
  if (free_no == -1) {
    no = ip_2_macs[device_no].no;
    if (no >= ip_2_macs[device_no].size) {
      if (ip_2_macs[device_no].size == 0) {
        ip_2_macs[device_no].size = 1024;
        ip_2_macs[device_no].data = (IP2MAC*)malloc(ip_2_macs[device_no].size * sizeof(IP2MAC));
      }
      else {
        ip_2_macs[device_no].size += 1024;
        ip_2_macs[device_no].data = (IP2MAC*)realloc(ip_2_macs[device_no].data,
                                  ip_2_macs[device_no].size * sizeof(IP2MAC));
      }
    }
    ip_2_macs[device_no].no++;
  }
  else {
    no = free_no;
  }
  ip2mac = &ip_2_macs[device_no].data[no];
  ip2mac->device_no = device_no;
  ip2mac->addr = addr;
  if (hwaddr == NULL) {
    ip2mac->flag = FLAG_NG;
    memset(ip2mac->hwaddr, 0, 6);
  }
  else {
    ip2mac->flag = FLAG_OK;
    memcpy(ip2mac->hwaddr, hwaddr, 6);
  }
  ip2mac->last_time = now;
  memset(&ip2mac->sd, 0, sizeof(SEND_DATA));
  pthread_mutex_init(&ip2mac->sd.mutex, NULL);

  debug_printf("Ip2Mac ADD [%d] %s = %d\n", device_no, in_addr_t2str(ip2mac->addr, buf, sizeof(buf)),no);
  return ip2mac;
}

int append_send_req_data(int device_no, int ip2mac_no) {
  SEND_REQ_DATA *d;
  int status;
  if ((status = pthread_mutex_lock(&send_req.mutex)) != 0) {
    debug_printf("AppendSendReqData: pthread_mutex_lock:%s\n", strerror(status));
    return -1;
  }
  for (d = send_req.top; d != NULL; d = d->next) {
    if (d->device_no == device_no && d->ip2mac_no == ip2mac_no) {
      pthread_mutex_unlock(&send_req.mutex);
      return 1;
    }
  }
  d = (SEND_REQ_DATA *)malloc(sizeof(SEND_REQ_DATA));
  if (d == NULL) {
    debug_printf("AppendSendReqData: malloc");
    pthread_mutex_unlock(&send_req.mutex);
    return -1;
  }
  d->next = d->before = NULL;
  d->device_no = device_no;
  d->ip2mac_no = ip2mac_no;

  if (send_req.bottom == NULL) {
    /* add initial element to empty list */
    send_req.top = send_req.bottom = d;
  }
  else {
    send_req.bottom->next = d;
    d->before = send_req.bottom;
    send_req.bottom = d;
  }
  pthread_cond_signal(&send_req.cond);
  pthread_mutex_unlock(&send_req.mutex);

  debug_printf("AppendSendReqData:[%d] %d\n", device_no, ip2mac_no);
  return 0;
}

int append_send_data(IP2MAC *ip2mac, int device_no, in_addr_t addr, u_char *data, int size) {
  SEND_DATA *sd = &ip2mac->sd;
  DATA_BUF *d;
  int status;
  char buf[80];

  if (sd->in_bucket_size > MAX_BUCKET_SIZE) {
    debug_printf("AppendSendData: Bucket overflow\n");
    return -1;
  }

  d = (DATA_BUF *)malloc(sizeof(DATA_BUF));
  if (d == NULL) {
    debug_perror("malloc");
    return -1;
  }
  d->data = (u_char *)malloc(size);
  if (d->data == NULL) {
    debug_perror("malloc");
    free(d);
    return -1;
  }
  d->next = d->before = NULL;
  d->t = time(NULL);
  d->size = size;
  memcpy(d->data, data, size);

  if ((status = pthread_mutex_lock(&sd->mutex)) != 0) {
    debug_printf("AppendSendData: pthread_mutex_lock:%s\n", strerror(status));
    free(d->data);
    free(d);
    return -1;
  }
  if (sd->bottom == NULL) {
    sd->top = sd->bottom = d;
  }
  else {
    sd->bottom->next = d;
    d->before = sd->bottom;
    sd->bottom = d;
  }
  sd->dno++;
  sd->in_bucket_size += size;
  pthread_mutex_unlock(&sd->mutex);

  debug_printf("AppendSendData:[%d] %s %dbytes(Total=%lu:%lubytes)\n",device_no,
              in_addr_t2str(addr,buf,sizeof(buf)), size, sd->dno, sd->in_bucket_size);
  return 0;
}

int get_send_data(IP2MAC *ip2mac, int *size, u_char **data) {
  SEND_DATA *sd = &ip2mac->sd;
  DATA_BUF *d;
  int status;
  char buf[80];

  if (sd->top == NULL) {
    return -1;
  }
  if ((status = pthread_mutex_lock(&sd->mutex)) != 0) {
    debug_printf("pthread_mutex_lock:%s\n", strerror(status));
    return -1;
  }
  d = sd->top;
  sd->top = d->next;
  if (sd->top == NULL) {
    sd->bottom = NULL;
  }
  else {
    sd->top->before = NULL;
  }
  sd->dno--;
  sd->in_bucket_size -= d->size;

  pthread_mutex_unlock(&sd->mutex);

  *size = d->size;
  *data = d->data;

  free(d);

  debug_printf("get_send_data:[%d] %s %dbytes\n", ip2mac->device_no, in_addr_t2str(ip2mac->addr, buf, sizeof(buf)), *size);
  return 0;
}

int free_send_data(IP2MAC *ip2mac) {
  SEND_DATA *sd = &ip2mac->sd;
  DATA_BUF *ptr;
  int status;
  char buf[80];
  if (sd->top == NULL) {
    return 0;
  }
  if ((status = pthread_mutex_lock(&sd->mutex)) != 0) {
    debug_printf("pthread_mutex_lock:%s\n",strerror(status));
    return -1;
  }
  for (ptr = sd->top; ptr != NULL; ptr = ptr->next) {
    free(ptr->data);
  }
  sd->top = sd->bottom = NULL;
  pthread_mutex_unlock(&sd->mutex);
  return 0;
}

int buffer_send() {
  struct timeval now;
  struct timespec timeout;
  int device_no,ip2mac_no;
  int status;
  while (1) {
    gettimeofday(&now, NULL);
    timeout.tv_sec = now.tv_sec + 1;
    timeout.tv_nsec = now.tv_usec * 1000;

    pthread_mutex_lock(&send_req.mutex);
    if ((status = pthread_cond_timedwait(&send_req.cond, &send_req.mutex, &timeout)) != 0) {
      //debug_printf("pthread_cond_timedwait:%s\n", strerror(status));
    }
    pthread_mutex_unlock(&send_req.mutex);

    /* Send all waiting datas */
    while (1) {
      if (get_send_req_data(&device_no, &ip2mac_no) == -1) {
        break;
      }
      buffer_send_one(device_no, &ip_2_macs[device_no].data[ip2mac_no]);
    }
  }
  debug_printf("BufferSend:end\n");
  return 0;
}

int get_send_req_data(int *device_no, int *ip2mac_no) {
  SEND_REQ_DATA *d;
  int status;
  if (send_req.top == NULL) {
    return -1;
  }
  if ((status = pthread_mutex_lock(&send_req.mutex)) != 0) {
    debug_printf("pthread_mutex_lock:%s\n",strerror(status));
    return -1;
  }
  d = send_req.top;
  send_req.top = d->next;
  if (send_req.top == NULL) {
    send_req.bottom = NULL;
  }
  else {
    send_req.top->before = NULL;
  }
  pthread_mutex_unlock(&send_req.mutex);
  *device_no = d->device_no;
  *ip2mac_no = d->ip2mac_no;

  debug_printf("GetSendReqData][%d]%d\n",*device_no, *ip2mac_no);
  return 0;
}

int buffer_send_one(int device_no, IP2MAC *ip2mac) {
  struct ether_header eh;
  struct iphdr iphdr;
  u_char option[1500];
  int option_len;
  int size;
  u_char *data;
  u_char *ptr;

  while (1) {
    if (get_send_data(ip2mac, &size, &data) == -1) {
      break;
    }
    ptr = data;
    memcpy(&eh, ptr, sizeof(struct ether_header));
    ptr += sizeof(struct ether_header);

    memcpy(&iphdr, ptr, sizeof(struct iphdr));
    ptr += sizeof(struct iphdr);

    option_len = iphdr.ihl * 4 - sizeof(struct iphdr);
    if (option_len > 0) {
      memcpy(option, ptr, option_len);
      ptr += option_len;
    }

    /* Change disination host MAC address. */
    memcpy(eh.ether_dhost, ip2mac->hwaddr, 6);
    memcpy(data, &eh, sizeof(struct ether_header));

    debug_printf("iphdr.ttl %d->%d\n",iphdr.ttl, iphdr.ttl - 1);
    iphdr.ttl--;

    iphdr.check = 0;
    iphdr.check = checksum2((u_char *)&iphdr,sizeof(struct iphdr), option, option_len);
    memcpy(data + sizeof(struct ether_header), &iphdr, sizeof(struct iphdr));

    debug_printf("write:BufferSendOne:[%d] %dbytes\n",device_no, size);
    write(device[device_no].soc, data, size);
  }
  return 0;
}

IP2MAC *ip_2_mac(int device_no, in_addr_t addr, u_char *hwaddr) {
  IP2MAC *ip2mac;
  static u_char bcast[6] = "\xff\xff\xff\xff\xff\xff";
  char buf[80];

  ip2mac = ip_2_mac_search(device_no, addr, hwaddr);
  if (ip2mac->flag == FLAG_OK) {
    debug_printf("Ip2Mac(%s):OK\n", in_addr_t2str(addr, buf, sizeof(buf)));
    return ip2mac;
  } else {
    debug_printf("Ip2Mac(%s):NG\n", in_addr_t2str(addr, buf, sizeof(buf)));
    debug_printf("Ip2Mac(%s):Send Arp Request\n", in_addr_t2str(addr, buf, sizeof(buf)));
    send_arp_requestb(device[device_no].soc, addr, bcast, device[device_no].addr.s_addr, device[device_no].hwaddr);
    return ip2mac;
  }
}

int print_ether_header(struct ether_header *eh, FILE *fp) {
  char buf[128];
  printf("print_ether\n");
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
