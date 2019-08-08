#pragma once

#include "include.h"

void arp_relay(char * dev, pcap_t * handle, uint8_t ** Senders_IP, uint8_t ** Targets_IP, uint8_t ** Senders_MAC, uint8_t ** Targets_MAC, int session_cnt);
