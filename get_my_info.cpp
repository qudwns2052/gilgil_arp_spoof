#include "get_my_info.h"

void GET_MY_IP_MAC(char * dev, uint8_t * ip_attacker, uint8_t * mac_attacker)
{
    /*        Get my IP Address      */
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;

    strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);

    ioctl(fd, SIOCGIFADDR, &ifr); // ???????

    close(fd);
    memcpy(ip_attacker, &((((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr).s_addr), 4);
/*************************************************************************************************/

    // MAC 주소 가져오는 부분인데 공부 해야 할듯. 이해 불가

    /*        Get my Mac Address      */
    struct ifconf ifc;
    char buf[1024];
    bool success = false;

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock == -1) { /* handle error*/ };

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) { /* handle error */ }

    ifreq* it = ifc.ifc_req;
    const ifreq* const end = it + (ifc.ifc_len / sizeof(ifreq));

    for (; it != end; ++it)
    {
      strcpy(ifr.ifr_name, it->ifr_name);
      if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0)
      {
              if (! (ifr.ifr_flags & IFF_LOOPBACK)) // don't count loopback
              {
                      if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0)
                      {
                              success = true;
                              break;
                      }
              }
      }
      else { /* handle error */ }
    }
    if (success) memcpy(mac_attacker, ifr.ifr_hwaddr.sa_data, 6);
}
