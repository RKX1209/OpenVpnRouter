#ifndef __PFKEY_V2_H__
#define __PFKEY_V2_H__

#define K_SADB_EXT_MAX        32

#define PF_KEY_V2             2
#define DIVUP(x, y) ((x + y - 1) / y)
#define PFKEYv2_ALIGN         (sizeof(u_int64_t) / sizeof(u_int8_t))

#define PFKEYv2_WORDS(x)      (DIVUP(x, PFKEYv2_ALIGN))
#define PFKEYv2_MAX_MSGSIZE   4096
typedef u_int32_t pfkey_seq_t;

enum pfkey_ext_required {
  EXT_BITS_IN = 0,
  EXT_BITS_OUT = 1
};

typedef union {
  unsigned char bytes[PFKEYv2_MAX_MSGSIZE];
  struct sadb_msg msg;
}pfkey_buf;

extern void pfkey_close(void);
extern void netlink_register_proto(unsigned satype, const char *satypename);
#endif
