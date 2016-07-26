#include <stdio.h>
#include <poll.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <pthread.h>
#include <signal.h>
#include <config.h>
#include "ipsec/ipsec.h"

int main() {
  init_ipsec();
  return 0;
}
