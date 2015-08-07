#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <linux/icmpv6.h>
#include <errno.h>
#include <signal.h>
#include <setjmp.h>
#include <sys/types.h>
#include <unistd.h>

#define BUFFER_SIZE 1500

int trace4(char *, char *, char [30][45]);
int trace6(char *, char *, char [30][45]);
