#pragma once

#include <iostream>
#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/ether.h>

#include "arp_infection.h"
#include "arp_relay.h"
#include "get_my_info.h"
#include "protocol_structure.h"


#define ETHER_HEADER_SIZE  14
#define ARP_HEADER_SIZE 28
