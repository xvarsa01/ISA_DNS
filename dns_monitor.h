#ifndef DNS_MONITOR_H
#define DNS_MONITOR_H


#include <stdio.h>
#include <stdlib.h>

#include <getopt.h>
#include <stdbool.h>
#include <string.h>

#define __USE_MISC 1
#include <pcap.h>

#include <netinet/in.h>
#include <netinet/ether.h>   // for struct ether_header
#include <netinet/ip.h>      // for struct ip
#include <netinet/ip6.h>
#include <netinet/tcp.h>     // for struct tcphdr
#include <netinet/udp.h>     // for struct udphdr

#include "params.h"
#include "general_utils.h"
#include "dns_utils.h"
#include <signal.h>

#endif