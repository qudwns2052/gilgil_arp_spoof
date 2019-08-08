#pragma once

#include "include.h"

void get_mac(pcap_t* handle, char * dev, uint8_t * Sender_IP, uint8_t * Sender_MAC);
bool arp_infection(pcap_t* handle, char * dev, uint8_t * Sender_IP, uint8_t * Target_IP, uint8_t * Sender_MAC, uint8_t * Target_MAC, bool First_time);

