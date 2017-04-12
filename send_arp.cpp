#include <cstdio>
#include <stdlib.h>
#include <cstdlib>
#include <iostream>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <cstring>

using namespace std;

#define PROMISCUOUS 1
#define	ETHERTYPE_ARP		0x0806

    struct ether_arp_hdr
    {
          unsigned char 	h_dest[6];	/* destination eth addr	*/
          unsigned char 	h_source[6];	/* source ether addr	*/
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


int value_change(int *argv, unsigned char *packet, char text[], int num) {

    /*
    int ipaddr = 0, i = 1;
    char *ipaddr3;

    ipaddr3 = strtok(argv, text);
    ipaddr = strtol(ipaddr3, NULL, num);
    packet[0] = ipaddr;
    cout << packet[0];

    while(ipaddr3 = strtok(NULL, text)) {
        ipaddr = strtol(ipaddr3, NULL, num);
        packet[i] = ipaddr;
        cout << packet[i];
        i++;
    }
   cout << endl;
    */
}


int main(char argc, char *argv[])
{

    struct ether_arp_hdr *eth_arp_hdr;
 //   eth_arp_hdr = (char *)malloc(42);

    pcap_t *pcd; // packet captuer descripter


    if (argc != 6) {
        cout << "Usage : " << argv[0] << " Device Target_ip Sender_ip My_mac Sender_mac";
        return -1;
    }

    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    dev = argv[1];
    cout << endl << "Device : " << dev << endl << endl;

    if ((pcd = pcap_open_live(dev, BUFSIZ, PROMISCUOUS, 500, errbuf)) == NULL) {
        cout << "Unable to open the Adapter.";
        return -1;
    }

    cout << "Ethernet Destination : ";
   // value_change(argv[5], eth_arp_hdr->h_dest, ":", 16);
    string hi;
    int j=0;
  //  for(int i=0; i<16; i++) {
   //     cout << target_mac;
  //  hi = target_mac.substr(i, 2); // 01 34 67 910 1213 1516 //
  //  cout << hi;
   // j++;
   // }

    cout << "Ethernet Source : ";
    //value_change(argv[4], eth_arp_hdr->h_source, ":", 16);

    eth_arp_hdr->h_proto = htons(ETHERTYPE_ARP);
    cout << "ether-type : " << eth_arp_hdr->h_proto << "\n\n";



    //packet += sizeof(struct ethhdr);
    //arp = (struct arphdr *)packet;

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


    cout << "Sender mac : ";
  //  value_change(argv[4], eth_arp_hdr->__ar_sha, ":", 16);
   // eth_arp_hdr->__ar_sha =


   // eth_arp_hdr->__ar_sip = inet_addr(argv[2]);
    cout << "Sender ip : ";
 //   value_change(argv[2], eth_arp_hdr->__ar_sip, ".", 10);


    cout << "Target mac : ";
//    value_change(argv[5], eth_arp_hdr->__ar_tha, ":", 16);



   // eth_arp_hdr->__ar_tip = inet_addr(argv[3]);
    cout << "Target ip : " << eth_arp_hdr->__ar_tip;
    //value_change(argv[3], eth_arp_hdr->__ar_tip, ".", 10);



    if (pcap_sendpacket(pcd, eth_arp_hdr, 42) != 0) {
        cout << "Error sending the packet" << endl;
        return -1;
    }
    else cout << endl << "Good" << endl;

}



