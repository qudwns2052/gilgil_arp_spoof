#pragma once

#include "include.h"

/* ETHERNET header */
typedef struct eth_header
{
    uint8_t  dmac[6];
    uint8_t  smac[6];
    uint16_t type;
}ETH_header;

/* ARP header */
typedef struct arp_header
{
    uint16_t htype;          /* Hardware Type           */
    uint16_t ptype;         /* Protocol Type           */
    uint8_t hlen;           /* Hardware Address Length */
    uint8_t plen;           /* Protocol Address Length */
    uint16_t oper;          /* Operation Code          */
    uint8_t smac[6];        /* Sender hardware address */
    uint8_t sip[4];         /* Sender IP address       */
    uint8_t dmac[6];        /* Target hardware address */
    uint8_t dip[4];         /* Target IP address       */
}ARP_header;

/* IP header */
typedef struct ip_header
{
    uint8_t VHL;
    uint8_t TOS;
    uint16_t Total_LEN;
    uint16_t Id;
    uint16_t Fragment;
    uint8_t TTL;
    uint8_t protocol;
    uint16_t checksum;
    uint8_t s_ip[4];
    uint8_t d_ip[4];
}IP_header;

/* TCP header */
typedef struct tcp_header
{
    uint16_t s_port;
    uint16_t d_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t OFF;
    uint8_t flag;
    uint16_t win_size;
    uint16_t check_sum;
    uint16_t urg_pointer;
}TCP_header;
