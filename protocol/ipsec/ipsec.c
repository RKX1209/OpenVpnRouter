#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <linux/netlink.h>
#include <linux/xfrm.h>
#include "ipsec/ipsec.h"
#include "ipsec/pfkeyv2.h"
#include "util.h"

static int netlinkfd = -1, netlink_bcast_fd = -1, pfkeyfd = -1;
struct kernel_ops *k_ops;
pid_t pid;
/* Supported algorithms */
struct sadb_alg esp_aalg[K_SADB_AALG_MAX+1];
struct sadb_alg esp_ealg[K_SADB_EALG_MAX+1];
int esp_ealg_num=0;
int esp_aalg_num=0;
enum kernel_interface k_interface = EOF;

void init_kinterface(void)
{
  switch (k_interface) {
  #ifdef CONFIG_NETKEY
  case USE_NETKEY:
    /* To enable pfkey interface, first of all, load "af_key" kernel module. */
    if (stat("/proc/net/pfkey", &buf) == 0) {
      k_interface = USE_NETKEY;
      k_ops = &netkey_kernel_ops;
      debug_printf("Use Linux XFRM/NETKEY interface\n");
      break;
    }
  #endif
  default:
    debug_perror("kernel interface not found\n");
    break;
  }
  if (k_ops->init) {
    k_ops->init();
  }
  if (k_ops->pfkey_register) {
    k_ops->pfkey_register();
  }
}

static void init_pfkey(void)
{
  pid = getpid();
  pfkeyfd = socket(PF_KEY, SOCK_RAW, PF_KEY_V2);
  if (pfkeyfd < 0)
    exit_error("init_pfkey: socket() failed\n");
  debug_printf("process %u listening for PEKeyv2 on %d fd", (unsigned)pid, pfkeyfd);
}

static struct sadb_alg *sadb_alg_ptr(int satype, int exttype, int alg_id, int rw)
{
  struct sadb_alg *alg_p = NULL;
  switch (satype) {
    case SADB_SATYPE_AH:
    case SADB_SATYPE_ESP:
      alg_p = (exttype == SADB_EXT_SUPPORTED_ENCRYPT) ?
              &esp_ealg[alg_id] : &esp_aalg[alg_id];
      if (rw) {
        (exttype == SADB_EXT_SUPPORTED_ENCRYPT) ?
        esp_ealg_num++ : esp_aalg_num++;
      }
      break;
    default:
    break;
  }
  return alg_p;
}
/* @function kernel_alg_add:
 * Add new algorithm specifed by argument to keymangaer internal table.(i.e. esp_(a|e)alg[alg_id])
 */
int kernel_alg_add(int satype, int exttype, const struct sadb_alg *sadb_alg)
{
  struct sadb_alg *alg_p = NULL;
  int alg_id = sadb_alg->sadb_alg_id;
  debug_printf("kernel_alg_add: satype=%d, exttype=%d, alg_id=%d\n", satype,
              exttype, sadb_alg);
  if (!(alg_p = sadb_alg_ptr(satype, exttype, alg_id, 1))) {
    debug_printf("kernel_alg_add: failed to add algorithm\n");
    return -1;
  }
  *alg_p = *sadb_alg;
  return 1;
}

static void linux_pfkey_add_aead(void)
{
  struct sadb_alg alg;
  alg.sadb_alg_reserved = 0;
  /* IPsec algos (encryption and authentication combined) */
	alg.sadb_alg_ivlen = 8;
	alg.sadb_alg_minbits = 128;
	alg.sadb_alg_maxbits = 256;
	alg.sadb_alg_id = SADB_X_EALG_AES_GCM_ICV8;
	if (kernel_alg_add(SADB_SATYPE_ESP, SADB_EXT_SUPPORTED_ENCRYPT, &alg) != 1)
		debug_printf("Warning: failed to register algo_aes_gcm_8 for ESP\n");

	alg.sadb_alg_ivlen = 12;
	alg.sadb_alg_minbits = 128;
	alg.sadb_alg_maxbits = 256;
	alg.sadb_alg_id = SADB_X_EALG_AES_GCM_ICV12;
	if (kernel_alg_add(SADB_SATYPE_ESP, SADB_EXT_SUPPORTED_ENCRYPT, &alg) != 1)
		debug_printf("Warning: failed to register algo_aes_gcm_12 for ESP\n");

	alg.sadb_alg_ivlen = 16;
	alg.sadb_alg_minbits = 128;
	alg.sadb_alg_maxbits = 256;
	alg.sadb_alg_id = SADB_X_EALG_AES_GCM_ICV16;
	if (kernel_alg_add(SADB_SATYPE_ESP, SADB_EXT_SUPPORTED_ENCRYPT, &alg) != 1)
		debug_printf("Warning: failed to register algo_aes_gcm_16 for ESP\n");

	/* keeping aes-ccm behaviour intact as before */
	alg.sadb_alg_ivlen = 8;
	alg.sadb_alg_minbits = 128;
	alg.sadb_alg_maxbits = 256;
	alg.sadb_alg_id = SADB_X_EALG_AES_CCM_ICV8;
	if (kernel_alg_add(SADB_SATYPE_ESP, SADB_EXT_SUPPORTED_ENCRYPT, &alg) != 1)
		debug_printf("Warning: failed to register algo_aes_ccm_8 for ESP\n");

	alg.sadb_alg_id = SADB_X_EALG_AES_CCM_ICV12;
	if (kernel_alg_add(SADB_SATYPE_ESP, SADB_EXT_SUPPORTED_ENCRYPT, &alg) != 1)
		debug_printf("Warning: failed to register algo_aes_ccm_12 for ESP\n");

	alg.sadb_alg_id = SADB_X_EALG_AES_CCM_ICV16;
	if (kernel_alg_add(SADB_SATYPE_ESP, SADB_EXT_SUPPORTED_ENCRYPT, &alg) != 1)
		debug_printf("Warning: failed to register algo_aes_ccm_16 for ESP\n");


}

static void linux_pfkey_register_response(const struct sadb_msg *msg)
{
  switch (msg->sadb_msg_satype)
  {
    /* What type of fresponse? */
    case SADB_SATYPE_ESP:
      //linux_pfkey_add_aead();
      break;
    default:
      break;
  }
}

static void linux_pfkey_register(void)
{
  netlink_register_proto(SADB_SATYPE_AH, "AH");
  netlink_register_proto(SADB_SATYPE_ESP, "ESP");
  //netlinke_register_proto(SADB_X_SATYPE_IPCOMP, "IPCOMP");
  pfkey_close();
}

static void init_netlink(void)
{
  struct sockaddr_nl addr;
  /* We'll use XFRM netlink interface of kernel. */
  netlinkfd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_XFRM);
  if (netlinkfd < 0)
    exit_error("init_netlink: socket() failed\n");

  netlink_bcast_fd =socket(AF_NETLINK, SOCK_DGRAM, NETLINK_XFRM);
  if (netlinkfd < 0)
    exit_error("init_netlink: socket() for bcast failed\n");

  addr.nl_family = AF_NETLINK;
  addr.nl_pid = getpid();
  addr.nl_groups = XFRMGRP_ACQUIRE | XFRMGRP_EXPIRE;
  if (bind(netlink_bcast_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
    exit_error("failed to bind bcast socket\n");

  init_pfkey();
}
const struct kernel_ops netkey_kernel_ops = {
  .kern_name = "netkey",
  .init = init_netlink, //when use netkey interface, we need initialize netlink at first
  .pfkey_register = linux_pfkey_register,
  .pfkey_register_response = linux_pfkey_register_response,

};
