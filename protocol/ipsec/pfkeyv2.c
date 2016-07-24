#include <arpa/inet.h>
#include <linux/pfkeyv2.h>
#include <linux/xfrm.h>
#include <sys/types.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include "ipsec/pfkeyv2.h"
#include "ipsec/ipsec.h"
#include "util.h"

int pfkeyfd = -1;
static pfkey_seq_t pfkey_seq = 0;

int pfkey_permitted_ext (int inout, int sadb_operation, int exttype)
{
  return 1;
}

void pfkey_ext_init(struct sadb_ext *extensions[K_SADB_EXT_MAX + 1])
{
  int i;
  for (i = 0; i <= K_SADB_EXT_MAX; i++) {
    extensions[i] = NULL;
  }
}

/* Build Base Message Header sadb_ext(sadb_msg) */
int pfkey_msg_hdr_build (struct sadb_ext** pfkey_ext,
                         u_int8_t msg_type, u_int8_t satype,
                         u_int8_t msg_errno, u_int32_t seq,
                         u_int32_t pid4msg)
{
  int error = 0;
  struct sadb_msg *pfkey_msg = (struct sadb_msg *)*pfkey_ext;
  debug_printf("pfkey_msg_hdr_build:\n");
  pfkey_msg = (struct sadb_msg*)malloc(sizeof(struct sadb_msg));
  *pfkey_ext = (struct sadb_ext*)pfkey_msg;
  if (pfkey_msg == NULL) {
    debug_perror("pfkey_msg_hdr_build: memory allocation failed\n");
  }
  memset(pfkey_msg, 0, sizeof(struct sadb_msg));
  pfkey_msg->sadb_msg_len = sizeof(struct sadb_msg) / PFKEYv2_ALIGN;

  pfkey_msg->sadb_msg_type = msg_type;
  pfkey_msg->sadb_msg_satype = satype;

  pfkey_msg->sadb_msg_version = PF_KEY_V2;
  pfkey_msg->sadb_msg_errno = msg_errno;
  pfkey_msg->sadb_msg_reserved = 0;
  pfkey_msg->sadb_msg_seq = seq;
  pfkey_msg->sadb_msg_pid = pid4msg;
  return error;
}

static bool pfkey_build (int error, const char *desc, const char *text_said
                        , struct sadb_ext *extentions[K_SADB_EXT_MAX + 1])
{
  if (errno == 0) {
    return true;
  }
  else {
    return false;
  }
}

int pfkey_msg_build (struct sadb_msg **pfkey_msg, struct sadb_ext *extensions[], int dir)
{
  int error = 0;
  unsigned int ext, total_size;
  struct sadb_ext *pfkey_ext;

  if (!extensions[0]) {
    error = EINVAL;
    debug_printf("pfkey_msg_build: extensions[0] must be specified\n");
    goto error_lb;
  }
  total_size = PFKEYv2_WORDS(sizeof(struct sadb_msg));
  for (ext = 1; ext <= K_SADB_EXT_MAX; ext++) {
    if (extensions[ext]) {
      total_size += (extensions[ext])->sadb_ext_len;
    }
  }
  *pfkey_msg = (struct sadb_msg*)malloc(total_size * PFKEYv2_ALIGN);
  if (*pfkey_msg == NULL) {
    debug_printf("pfkey_msg_build: pfkey_msg memory allocation failed\n");
    error = ENOMEM;
  }

  memcpy(*pfkey_msg, extensions[0], sizeof(struct sadb_msg));
  (*pfkey_msg)->sadb_msg_len = total_size;
  (*pfkey_msg)->sadb_msg_reserved = 0;
  //extension_seen = 1;

  pfkey_ext = (struct sadb_ext*)(((char *)(*pfkey_msg)) + sizeof(struct sadb_msg));
  for (ext = 1; ext <= K_SADB_EXT_MAX; ext++) {
    if (extensions[ext]) {
      if (!pfkey_permitted_ext(dir, (*pfkey_msg)->sadb_msg_type,ext)) {
        debug_printf("ext type %d not permitted\n", ext);
        error = EINVAL;
        goto error_lb;
      }
      memcpy(pfkey_ext, extensions[ext], (extensions[ext])->sadb_ext_len * PFKEYv2_ALIGN);
      char pfkey_ext_c = (char)pfkey_ext;
      pfkey_ext_c += (extensions[ext])->sadb_ext_len * PFKEYv2_ALIGN;
      pfkey_ext = (struct sadb_ext *)pfkey_ext_c;
    }
  }

error_lb:
  return error;
}

static bool pfkey_get(pfkey_buf * buf)
{
  for (;;)
  {
    ssize_t len;
    len = read(pfkeyfd, buf->bytes, sizeof(buf->bytes));
    if (len < 0)
    {
      debug_perror("pfkey_get: read() failed\n");
      return false;
    }

  }
}

static bool pfkey_get_response (pfkey_buf *buf, pfkey_seq_t seq)
{
  while (pfkey_get(buf))
  {
    if (buf->msg.sadb_msg_pid == (unsigned)pid &&
        buf->msg.sadb_msg_seq == seq)
    {
      return true;
    }
    else
    {

    }
  }
  return false;
}

static bool pfkey_msg_start (u_int8_t msg_type, u_int8_t satype,
                            const char *desc, const char *text_said,
                            struct sadb_ext *extensions[K_SADB_EXT_MAX + 1])
{
  pfkey_ext_init(extensions);
  return pfkey_build(pfkey_msg_hdr_build(&extensions[0], msg_type,
                                          satype, 0, ++pfkey_seq, pid)
                                        , desc, text_said, extensions);
}

static bool finish_pfkey_msg (struct sadb_ext *extensions[K_SADB_EXT_MAX + 1]
                              , const char *desc, const char *text_said
                              , pfkey_buf *response)
{
  struct sadb_msg *pfkey_msg;
  bool success = true;
  int error;

  error = pfkey_msg_build(&pfkey_msg, extensions, EXT_BITS_IN);
  if (error != 0)
  {
    debug_printf("pfkey_msg_buid of %s %s failed, code%d\n", desc, text_said, error);
    success = false;
  }
  else
  {
    size_t len = pfkey_msg->sadb_msg_len * PFKEYv2_ALIGN;
    if (k_interface != NO_KERNEL)
    {
      ssize_t r = write(pfkeyfd, pfkey_msg, len);
      {
        /* Check response from kernel. */
        pfkey_buf *bp = response;
        int seq = ((struct sadb_msg *)extensions[0])->sadb_msg_seq;
        if (!pfkey_get_response(bp, seq))
        {
          debug_printf("ERROR: no response from kernel\n");
          success = false;
        }
      }
    }
  }
  return success;
}

static void pfkey_register(unsigned int sadb_register, unsigned satype,
                          const char *satypename)
{
  struct sadb_ext *extensions[K_SADB_EXT_MAX + 1];
  pfkey_buf pfb;

  /* Build extension messages and send these by 'finish_pfkey_msg' function. */
  if (!(pfkey_msg_start(sadb_register, satype, satypename, NULL, extensions)
      && finish_pfkey_msg(extensions, satypename, "", &pfb)))
  {
    debug_printf("no kernel support %s\n", satypename);
  }
  else
  {
    /* Sending messages to kernel has completed.
     * Now kernel is returning response. */
    k_ops->pfkey_register_response(&pfb.msg);
    debug_printf("%s registered with kernel.\n", satypename);
  }
}

void pfkey_close(void)
{
  close(pfkeyfd);
  pfkeyfd = -1;
}

void netlink_register_proto(unsigned satype, const char *satypename)
{
  return pfkey_register(SADB_REGISTER, satype, satypename);
}
