#if 0
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include <string.h>

#define hardware_type 0x0001
#define protocol_type 0x0800

typedef struct arp_packet{
    u_int16_t hw_type;
    u_int16_t pt_type;
    u_int8_t hw_len;
    u_int8_t pt_len;
    //u_int8_t eth;
    u_int16_t opcode;
    u_char sender_mac[6];
    u_int32_t sender_ip;
    u_int64_t target_mac;
    u_int32_t target_ip;
} arp_packet;

int main(int argc, char * argv[] )
{

    u_char sender_ip[4];
   for(int i =0 ; i<4 ;i++)
   {
       sender_ip[i]= inet_addr(argv[2])>>(8*i)& 0xff;
   }

    u_char target_ip[4];
      for(int i =0 ; i<4 ;i++)
      {
          target_ip[i]= inet_addr(argv[3])>>(8*i)& 0xff;
      }
printf("%2x %2x %2x %2x test\n", sender_ip[0],sender_ip[1],sender_ip[2],sender_ip[3]);
struct ifreq ifr;
struct ifconf ifc;
char buf[1024];
int success = 0;

int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
if (sock == -1) { /* handle error*/ };

ifc.ifc_len = sizeof(buf);
ifc.ifc_buf = buf;
if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) { /* handle error */ }

struct ifreq* it = ifc.ifc_req;
const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

for (; it != end; ++it) {
    strcpy(ifr.ifr_name, it->ifr_name);
    if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
        if (! (ifr.ifr_flags & IFF_LOOPBACK)) { // don't count loopback
            if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                success = 1;
                break;
            }
        }
    }
    else { /* handle error */ }
}

unsigned char mac_address[6]={0,};
if (success) memcpy(mac_address,ifr.ifr_hwaddr.sa_data, 6);
    printf("1");
    struct arp_packet arpcat;
    memset(arpcat.target_mac,0xff,6);
    arpcat.hw_type = 0x0001;
    arpcat.pt_type= 0x0800;
    arpcat.hw_len = 0x06;
    arpcat.pt_len = 0x04;
    arpcat.opcode = 0x0100;
    memcpy(arpcat.sender_mac, mac_address,6);
     memcpy(arpcat.sender_ip,sender_ip ,4);
     memcpy(arpcat.target_ip, target_ip,4);

    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
   fprintf(stderr, "cot open device %s: %s\n", dev, errbuf);
       return -1;
     }


        pcap_sendpacket(handle,&arpcat,42);

//    printf("%02x:%02x:%02x:%02x:%0x:%02x\n",mac_address[0],mac_address[1],mac_address[2],mac_address[3],mac_address[4],mac_address[5]);
    while (1) {
        struct pcap_pkthdr* header;
        const u_char* pacre;
        u_char smac[6];
        pcap_next_ex(handle,&header, &pacre);
        printf("%u bytes captured\n" ,header->caplen);
        if(pacre[12] == 0x08&& pacre[13] == 0x06)
        {
            printf("ARP packet\n");
            if(pacre[20] == 0x00 && pacre[21] ==0x02)
            {  printf("ARP Reply packet");
                smac[0] = pacre[22];
                smac[1] = pacre[23];
                smac[2] = pacre[24];
                smac[3] = pacre[25];
                smac[4] = pacre[26];
                smac[5] = pacre[27];
                break;
            }
         }

            }

            }

        }

    }
}
#endif

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include <string.h>

#define hardware_type 0x0001
#define protocol_type 0x0800

typedef struct arp_packet{
    u_int16_t hw_type;
    u_int16_t pt_type;
    u_int8_t hw_len;
    u_int8_t pt_len;
    //u_int8_t eth;
    u_int16_t opcode;
    u_char sender_mac[6];
    u_int32_t sender_ip;
    u_int64_t target_mac;
    u_int32_t target_ip;
} arp_packet;

int main(int argc, char * argv[] )
{

    u_char sender_ip[4];
   for(int i =0 ; i<4 ;i++)
   {
       sender_ip[i]= inet_addr(argv[2])>>(8*i)& 0xff;
   }
    u_char target_ip[4];
      for(int i =0 ; i<4 ;i++)
      {
          target_ip[i]= inet_addr(argv[3])>>(8*i)& 0xff;
      }
    struct ifreq ifr;
    struct ifconf ifc;
    char buf[1024];
    int success = 0;

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock == -1) { /* handle error*/ };

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) { /* handle error */ }

    struct ifreq* it = ifc.ifc_req;
    const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

    for (; it != end; ++it) {
        strcpy(ifr.ifr_name, it->ifr_name);
        if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
            if (! (ifr.ifr_flags & IFF_LOOPBACK)) { // don't count loopback
                if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                    success = 1;
                    break;
                }
            }
        }
        else { /* handle error */ }
    }

    unsigned char mac_address[6]={0, };
    if (success) memcpy(mac_address,ifr.ifr_hwaddr.sa_data, 6);
        printf("1");
        struct arp_packet arpcat;
        memset(arpcat.target_mac,0xff,6);
        arpcat.hw_type = 0x0001;
        arpcat.pt_type= 0x0800;
        arpcat.hw_len = 0x06;
        arpcat.pt_len = 0x04;
        arpcat.opcode = 0x0100;
        memcpy(arpcat.sender_mac, mac_address,6);
        memcpy(arpcat.sender_ip,sender_ip ,4);
        memcpy(arpcat.target_ip, target_ip,4);

        char *dev = argv[1];
        char errbuf[PCAP_ERRBUF_SIZE];

        pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

        if (handle == NULL) {
       fprintf(stderr, "cot open device %s: %s\n", dev, errbuf);
           return -1;
         }


            pcap_sendpacket(handle,&arpcat,42);

    //    printf("%02x:%02x:%02x:%02x:%0x:%02x\n",mac_address[0],mac_address[1],mac_address[2],mac_address[3],mac_address[4],mac_address[5]);
        while (1) {
            struct pcap_pkthdr* header;
            const u_char* pacre;
            u_char smac[6];
            pcap_next_ex(handle,&header, &pacre);
            printf("%u bytes captured\n" ,header->caplen);
            if(pacre[12] == 0x08&& pacre[13] == 0x06)
            {
                printf("ARP packet\n");
                if(pacre[20] == 0x00 && pacre[21] ==0x02)
                {  printf("ARP Reply packet");
                    smac[0] = pacre[22];
                    smac[1] = pacre[23];
                    smac[2] = pacre[24];
                    smac[3] = pacre[25];
                    smac[4] = pacre[26];
                    smac[5] = pacre[27];
                    break;
                }
             }

}

}
