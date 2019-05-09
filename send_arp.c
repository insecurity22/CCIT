#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <net/if_arp.h>

#define PROMISCUOUS 1

struct ether_arp_hdr {
    unsigned char	h_dest[ETH_ALEN];	/* destination eth addr	*/
    unsigned char	h_source[ETH_ALEN];	/* source ether addr	*/
    __be16        h_proto;              /* packet type ID field	*/

    unsigned short int ar_hrd;      	/* Format of hardware address.  */
    unsigned short int ar_pro;      	/* Format of protocol address.  */
    unsigned char ar_hln;               /* Length of hardware address.  */
    unsigned char ar_pln;               /* Length of protocol address.  */
    unsigned short int ar_op;           /* ARP opcode (command).  */

    unsigned char __ar_sha[ETH_ALEN];	/* Sender hardware address.  */
    unsigned char __ar_sip[4];          /* Sender IP address.  */
    unsigned char __ar_tha[ETH_ALEN];	/* Target hardware address.  */
    unsigned char __ar_tip[4];          /* Target IP address.  */
};

int value_change(char *argv, unsigned char *packet, char text[], int num) {

    int hexvalue = 0, i = 1;
    char *longvalue;
    char *original = malloc(sizeof(char));
    strcpy(original, argv);

    longvalue = strtok(argv, text);
    hexvalue = strtol(longvalue, NULL, num);
    packet[0] = hexvalue;
    if(num==10) {
        printf("%d.", packet[0]);
    } else printf("%02x:", packet[0]);

    while(longvalue = strtok(NULL, text)) { /* longvalue = hexvalue */
        hexvalue = strtol(longvalue, NULL, num);
        packet[i] = hexvalue;
        if(num==10) {
            printf("%d", packet[i]);
            if(i!=3) printf(".");
        } else {
            printf("%02x", packet[i]);
            if(i!=5) printf(":");
        }
        i++;
    }
    printf("\n");

    return original;
}

int main(int argc, char *argv[])
{
    struct ether_arp_hdr *eth_arp_hdr;

    pcap_t *pcd; // packet captuer descripter
    char *dev; // device
    char errbuf[PCAP_ERRBUF_SIZE];
    char *original2;
    char *original = malloc(sizeof(char));

    if (argc != 6) {
        printf("Usage : %s Device Sender_ip Target_ip Sender_mac Target_mac\n\n", argv[0]);
        return -1;
    }

    dev = argv[1];
    printf("\n\n\n", dev);

    if ((pcd = pcap_open_live(dev, BUFSIZ, PROMISCUOUS, 500, errbuf)) == NULL) {
        printf("Unable to open the Adapter.");
        return -1;
    }

    eth_arp_hdr = (char *)malloc(42);
    printf("Ethernet Destination : ");
    original = value_change(argv[5], eth_arp_hdr->h_dest, ":", 16);

    printf("Ethernet Source : ");
    original2 = value_change(argv[4], eth_arp_hdr->h_source, ":", 16);

    eth_arp_hdr->h_proto = htons(ETHERTYPE_ARP);
    printf("Ether type : 0x0%x\n\n", htons(eth_arp_hdr->h_proto));

    //packet += sizeof(struct ethhdr);
    //arp = (struct arphdr *)packet;

    // ARP data
    eth_arp_hdr->ar_hrd = 0x0001;
    printf("ar_hdr : %04x\n", eth_arp_hdr->ar_hrd);
    eth_arp_hdr->ar_pro = 0x0800;
    printf("ar_pro : %04x\n", eth_arp_hdr->ar_pro);
    eth_arp_hdr->ar_hln = 0x06;
    printf("ar_hln : %02x\n", eth_arp_hdr->ar_hln); // hardware size
    eth_arp_hdr->ar_pln = 0x04;
    printf("ar_pln : %02x\n", eth_arp_hdr->ar_pln); // protocol size
    eth_arp_hdr->ar_op = 0x0002;
    printf("ar_op : %04x\n\n", eth_arp_hdr->ar_op);

    printf("Sender MAC : ");
    strcpy(argv[4], original);
    value_change(argv[4], eth_arp_hdr->__ar_sha, ":", 16);

    printf("Sender IP : ");
    value_change(argv[2], eth_arp_hdr->__ar_sip, ".", 10);

    printf("Target MAC : ");
    strcpy(argv[5], original2);
    value_change(argv[5], eth_arp_hdr->__ar_tha, ":", 16);

   // eth_arp_hdr->__ar_tip = inet_addr(argv[3]);
    printf("Target IP : ", eth_arp_hdr->__ar_tip);
    value_change(argv[3], eth_arp_hdr->__ar_tip, ".", 10);

    if (pcap_sendpacket(pcd, eth_arp_hdr, 42) != 0) {
        printf("----> Error send ARP packet\n");
        return -1;
    }
    else printf("\n\n----> Send ARP packet\n\n\n");
}
