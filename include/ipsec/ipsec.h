#ifndef __IPSEC_H__
#define __IPSEC_H__

#include <linux/pfkeyv2.h>

enum kernel_interface { NOP, USE_NETKEY, NO_KERNEL };

extern enum kernel_interface k_interface;

struct kernel_ops {
  enum kernel_interface type;
  const char *kern_name;
  void (*init)(void);
  void (*pfkey_register)(void);
  void (*pfkey_register_response)(const struct sadb_msg *msg);
};

#define K_SADB_AALG_MAX   255
#define K_SADB_EALG_MAX   255
extern struct kernel_ops *k_ops;
extern void init_ipsec(void);
extern pid_t pid;

#endif
