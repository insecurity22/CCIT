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


int main(int argc, char *argv[])
{

    struct ethhdr *ep;
    struct arphdr *arp;
    struct sockaddr_in server_addr;

    pcap_t *pcd; // packet captuer descripter
    char *dev; // device
    char errbuf[PCAP_ERRBUF_SIZE];
    const u_char *packet;
    unsigned char ipaddr2[20] = { 0, };

    unsigned int ipaddr = 0;

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
    arp = (struct arphdr *)packet;


    // Ethernet data
    strcpy(ep->h_dest, argv[5]);
    printf("Ethernet Destination : %s\n", ep->h_dest);

    strcpy(ep->h_source, argv[4]);
    printf("Ethernet Source : %s\n", ep->h_source);

    ep->h_proto = ETHERTYPE_ARP;
    printf("ether-type : 0x0%x\n\n", ep->h_proto);



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
    printf("ar_op : %02x\n", arp->ar_op);



    strcpy(arp->__ar_sha, argv[4]);
    printf("\nSender mac : %s\n", arp->__ar_sha);


    // 1
    ipaddr = htonl(inet_addr(argv[2]));
    arp->__ar_sip[0] = ipaddr;
    printf("REAL IP : %x\n", ipaddr);
    printf("REAL IP : %x\n", arp->__ar_sip);

    // 2
    server_addr.sin_addr.s_addr = htonl(inet_addr(argv[2]));
    // arp->__ar_sip= server_addr.sin_addr.s_addr;
    //  sprintf(arp->__ar_sip, "%d", server_addr.sin_addr.s_addr);
    for (int i = 0; i<10; i++){
        arp->__ar_sip[i] = server_addr.sin_addr.s_addr;
    }
    printf("Sender ip  : %02x\n", arp->__ar_sip);
    printf("*** %s -> %02x\n", argv[2], arp->__ar_sip);


    strcpy(arp->__ar_tha, argv[5]);
    printf("Target mac : %s\n", arp->__ar_tha);


    server_addr.sin_addr.s_addr = htonl(inet_addr(argv[3]));

    //  arp->__ar_tip = server_addr.sin_addr.s_addr;
    sprintf(arp->__ar_tip, "%d", server_addr.sin_addr.s_addr);
    printf("Target ip  : %02x\n", arp->__ar_tip);
    printf("*** %s -> %02x\n\n\n", argv[3], arp->__ar_tip);


    if (pcap_sendpacket(pcd, packet, 60) != 0) {
        printf("Error sending the packet\n");
        return -1;
    }

}




