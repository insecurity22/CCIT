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


int value_change(char *argv, unsigned char *packet, char text[]) {

    int ipaddr = 0;
    char *ipaddr3;
    int i=1;
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
    struct ethhdr *ep;
    struct arphdr *arp;
  //  struct sockaddr_in server_addr;

    pcap_t *pcd; // packet captuer descripter
    char *dev; // device
    char errbuf[PCAP_ERRBUF_SIZE];
    const u_char *packet;
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



    ep = (struct ethhdr *)packet;
    packet = (char *)malloc(42);

    printf("Ethernet Destination : ");
    original = value_change(argv[5], ep->h_dest, ":");

    printf("Ethernet Source : ");
    original2 = value_change(argv[4], ep->h_source, ":");

    ep->h_proto = htons(ETHERTYPE_ARP);
    printf("ether-type : 0x0%x\n\n", ep->h_proto);





    packet += sizeof(struct ethhdr);
    arp = (struct arphdr *)packet;

    // ARP data
    arp->ar_hrd = 0x0001;
    printf("ar_hdr : %02x\n", arp->ar_hrd);
    arp->ar_pro = 0x0800;
    printf("ar_pro : %02x\n", arp->ar_pro);
    arp->ar_hln = 0x06;
    printf("ar_hln : %02x\n", arp->ar_hln);
    arp->ar_pln = 0x04;
    printf("ar_pln : %02x\n", arp->ar_pln);
    arp->ar_op = 0x0002;
    printf("ar_op : %02x\n\n", arp->ar_op);


    printf("Sender mac : ");
    strcpy(argv[4], original);
    value_change(argv[4], arp->__ar_sha, ":");


    printf("Sender ip : ");
    value_change(argv[2], arp->__ar_sip, ".");


    printf("Target mac : ");
    strcpy(argv[5], original2);
    value_change(argv[5], arp->__ar_tha, ":");


    printf("Target ip : ");
    value_change(argv[3], arp->__ar_tip, ".");


    if (pcap_sendpacket(pcd, ep, 42) != 0) {
        printf("Error sending the packet\n");
        return -1;
    }
}

