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

    struct ether_arp_hdr
    {
          unsigned char	h_dest[ETH_ALEN];	/* destination eth addr	*/
          unsigned char	h_source[ETH_ALEN];	/* source ether addr	*/
          __be16        h_proto;		/* packet type ID field	*/


          unsigned short int ar_hrd;		/* Format of hardware address.  */
          unsigned short int ar_pro;		/* Format of protocol address.  */
          unsigned char ar_hln;		/* Length of hardware address.  */
          unsigned char ar_pln;		/* Length of protocol address.  */
          unsigned short int ar_op;		/* ARP opcode (command).  */

          unsigned char __ar_sha[ETH_ALEN];	/* Sender hardware address.  */
          unsigned int __ar_sip;		/* Sender IP address.  */
          unsigned char __ar_tha[ETH_ALEN];	/* Target hardware address.  */
          unsigned int __ar_tip;		/* Target IP address.  */

    };


int value_change(char *argv, unsigned char *packet, char text[]) {

    int ipaddr = 0, i = 1;
    char *ipaddr3;
    char *original = malloc(sizeof(char));

    strcpy(original, argv);

    ipaddr3 = strtok(argv, text);
    ipaddr = strtol(ipaddr3, NULL, 16);
    packet[0] = ipaddr;
    printf("%02x ", packet[0]);

    while(ipaddr3 = strtok(NULL, text)) {
        ipaddr = strtol(ipaddr3, NULL, 16);
        packet[i] = ipaddr;
        printf("%02x ", packet[i]);
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
   // const u_char *packet;
    char *original;
    char *original2;



    if (argc != 6) {
        printf("Usage : %s Device Sender_ip Target_ip Sender_mac Target_mac", argv[0]);
        return -1;
    }
    dev = argv[1];
    printf("\n\n\nDevice : %s\n\n", dev);

    if ((pcd = pcap_open_live(dev, BUFSIZ, PROMISCUOUS, 500, errbuf)) == NULL) {
        printf("Unable to open the Adapter.");
        return -1;
    }



    eth_arp_hdr = (char *)malloc(42);

    printf("Ethernet Destination : ");
    original = value_change(argv[5], eth_arp_hdr->h_dest, ":");

    printf("Ethernet Source : ");
    original2 = value_change(argv[4], eth_arp_hdr->h_source, ":");

    eth_arp_hdr->h_proto = htons(ETHERTYPE_ARP);
    printf("ether-type : 0x0%x\n\n", eth_arp_hdr->h_proto);



    //packet += sizeof(struct ethhdr);
    //arp = (struct arphdr *)packet;

    // ARP data
    eth_arp_hdr->ar_hrd = htons(0x0001);
    printf("ar_hdr : %02x\n", eth_arp_hdr->ar_hrd);
    eth_arp_hdr->ar_pro = htons(0x0800);
    printf("ar_pro : %02x\n", eth_arp_hdr->ar_pro);
    eth_arp_hdr->ar_hln = 0x06;
    printf("ar_hln : %02x\n", eth_arp_hdr->ar_hln);
    eth_arp_hdr->ar_pln = 0x04;
    printf("ar_pln : %02x\n", eth_arp_hdr->ar_pln);
    eth_arp_hdr->ar_op = htons(0x0002);
    printf("ar_op : %02x\n\n", eth_arp_hdr->ar_op);


    printf("Sender mac : ");
    strcpy(argv[4], original);
    value_change(argv[4], eth_arp_hdr->__ar_sha, ":");

    eth_arp_hdr->__ar_sip = (int *)malloc(14);
    eth_arp_hdr->__ar_sip = inet_addr(argv[2]);
    printf("Sender ip  : %02x\n", eth_arp_hdr->__ar_sip);

    printf("Target mac : ");
    strcpy(argv[5], original2);
    value_change(argv[5], eth_arp_hdr->__ar_tha, ":");



    eth_arp_hdr->__ar_tip = inet_addr(argv[3]);
    printf("Target ip  : %02x\n", eth_arp_hdr->__ar_tip);



    if (pcap_sendpacket(pcd, eth_arp_hdr, 42) != 0) {
        printf("Error sending the packet\n");
        return -1;
    }
    else printf("good");
}



