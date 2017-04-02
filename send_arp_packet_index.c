
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

#define PROMISCUOUS 1

struct arphdr
  {
    unsigned short int ar_hrd;		/* Format of hardware address.  */
    unsigned short int ar_pro;		/* Format of protocol address.  */
    unsigned int ar_hln;		/* Length of hardware address.  */
    unsigned int ar_pln;		/* Length of protocol address.  */
    unsigned short int ar_op;		/* ARP opcode (command).  */

    unsigned char ar_sha[ETH_ALEN];	/* Sender hardware address.  */
    unsigned char ar_sip[4];		/* Sender IP address.  */
    unsigned char ar_tha[ETH_ALEN];	/* Target hardware address.  */
    unsigned char ar_tip[4];		/* Target IP address.  */

  };


int main(int argc, char *argv[])
{

    struct ethhdr *ep;
    struct arphdr *arp;
    char *dev; // device
    char errbuf[PCAP_ERRBUF_SIZE];
    char name[20];

    pcap_t *pcd; // packet captuer descripter
    u_char packet[1000];

//    struct sockaddr_in sa;
//    struct in_addr laddr;
    int i=0, j=0;
    unsigned int ipaddr = 0;

    if(argc != 6) {
        printf("Usage : %s Device Sender_ip Target_ip Sender_mac Target_mac", argv[0]);
        return -1;
    }


    dev = argv[1]; // device name
    printf("Device : %s\n\n", dev);


    if((pcd = pcap_open_live(dev, BUFSIZ, PROMISCUOUS, 500, errbuf)) == NULL) {
        printf("Unable to open the Adapter.");
        return -1;
    }

    ep = (struct ethhdr *)packet;
    arp = (struct arphdr *)packet;


    // Ethernet
    printf("Ethernet Destination : ");
    for(i=0;i<=12;i++) {
        ep->h_dest[i] = argv[5][i];
        packet[i]=ep->h_dest[i];
        printf("%c", packet[i]);
    }


    printf("\n\nEthernet Source : ");
    for(i=13;i<=24;i++) {
        ep->h_source[i] = argv[4][j];
        packet[i]=ep->h_source[i];
        j++;
        printf("%c", packet[i]);
    }


    printf("\n\nEther-type : 0x");
    packet[25] = 0x08;
    packet[26] = 0x06;
    for(i=25; i<=26; i++) {
        printf("%02x", packet[i]);
    }


    // ARP
    printf("\nar_hdr : ");
    arp->ar_hrd = 0x0001;
    packet[27] = 0x01;
    packet[28] = 0x00;
    for(i=27; i<=28; i++) {
        printf("%02x", packet[i]);
    }


    printf("\nar_pro : ");
    arp->ar_pro = 0x0800;
    packet[29] = 0x08;
    packet[30] = 0x00;
    for(i=29; i<=30; i++) {
        printf("%02x", packet[i]);
    }

    arp->ar_hln = 0x06;
    printf("\nar_hln : ");
    packet[31] = arp->ar_hln;
    printf("%02x", packet[31]);

    arp->ar_pln = 0x04;
    printf("\nar_pln : ");
    packet[32] = arp->ar_pln;
    printf("%02x", packet[32]);

    arp->ar_op = 2;
    printf("\nar_op : ");
    packet[33] = 0x02;
    packet[34] = 0x00;
    for(i=33; i<=34; i++) {
        printf("%02x", packet[i]);
    }

    j=0;
    //strcpy(arp->ar_sha, argv[4]);
    printf("\n\nSender mac : ");
    for(i=35;i<=46;i++) {
        arp->ar_sha[j] = argv[4][j];
        packet[i] = arp->ar_sha[j];
        j++;
        printf("%c", packet[i]);
}

    // ---------------------------------------
ipaddr = htonl(inet_addr(argv[2])); // ipaddr = int
//packet[i]=inet_pton(AF_INET, argv[2][j], &(sa.sin_addr));//arp->ar_sip[j];
printf("\n\n***** Real : %s -> %x........... \n", argv[2], ipaddr);
    // ---------------------------------------

    printf("Sender ip  : ");
    struct sockaddr_in server_addr;
    server_addr.sin_addr.s_addr = htonl(inet_addr(argv[2]));
  //  ipaddr = server_addr.sin_addr.s_addr;
    sprintf(name, "%x", server_addr.sin_addr.s_addr);


   j=0;
   for(i=47;i<=58;i++) {
        packet[i] = name[j];
        j++;
        printf("%c", packet[i]);
   }


    j=0;
    //strcpy(arp->ar_tha, argv[5]);
    printf("\nTarget mac : ");
    for(i=59;i<=70;i++) {
        arp->ar_tha[j] = argv[5][j];
        packet[i]=arp->ar_tha[j];
        j++;
        printf("%c", packet[i]);
    }
    printf("\n\n");

    // ---------------------------------------
      ipaddr = htonl(inet_addr(argv[3])); // ipaddr = int
      //packet[i]=inet_pton(AF_INET, argv[2][j], &(sa.sin_addr));//arp->ar_sip[j];
      printf("\n***** Real : %s -> %x........... \n", argv[3], ipaddr);
    // ---------------------------------------

    server_addr.sin_addr.s_addr = htonl(inet_addr(argv[3]));
    //  ipaddr = server_addr.sin_addr.s_addr;
    sprintf(name, "%x", server_addr.sin_addr.s_addr);

    j=0;
    printf("Target ip : ");
    for(i=71;i<=82;i++) {
        packet[i] = name[j];
        j++;
        printf("%c", packet[i]);
    }
    printf("\n\n");


    if(pcap_sendpacket(pcd, packet, sizeof(packet))>=0) {
        printf("Error sending the packet\n");
        return -1;
    }
}



