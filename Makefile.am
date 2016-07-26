bin_PROGRAMS    =     vrouter ipsec
vrouter_SOURCES =     protocol/ethernet.c protocol/ipv4.c protocol/icmp.c protocol/arp.c router.c util.c
vrouter_CFLAGS  =     -Wall -fexceptions -fstack-protector-all -D_FORTIFY_SOURCE=2 -pthread -I./include
ipsec_SOURCES =       protocol/ipsec/ipsec.c protocol/ipsec/pfkeyv2.c ipsec_main.c util.c
ipsec_CFLAGS  =       -Wall -fexceptions -fstack-protector-all -D_FORTIFY_SOURCE=2 -pthread -I./include
