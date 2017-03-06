#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <pcap.h>
#include <errno.h>
#include <arpa/inet.h>

#define ETHER_ADDR_LEN 6


struct libnet_ether_addr {
        u_int8_t ether_addr_octet[6];
};

struct libnet_ethernet_hdr {
        u_int8_t ether_dhost[ETHER_ADDR_LEN];
        u_int8_t ether_shost[ETHER_ADDR_LEN]; 
        u_int16_t ether_type; 
};


struct libnet_ipv4_hdr {

u_int8_t ip_hl:4; 
struct in_addr ip_src;
struct in_addr ip_dst; 
};


struct libnet_tcp_hdr {
        u_int16_t th_sport;
        u_int16_t th_dport; 
};


struct libnet_ipv4_hdr *iph;
struct libnet_tcp_hdr *tcph;


void callback(u_char *useless, const struct pcap_pkthdr *pkthdr,
                const u_char *packet)
{
    struct libnet_ethernet_hdr *ep;
    unsigned short ether_type;

    ep = (struct libnet_ethernet_hdr *)packet;
    packet += sizeof(struct libnet_ethernet_hdr);
    ether_type = ntohs(ep->ether_type);

	printf("\n***** Ethernet *****\n");
	printf("Src mac : [");
	for(int i=0; i<6; i++) {
	printf("%02x", ep->ether_shost[i]);
	if(i!=5) printf(":");
	}
	printf("] \n");

	printf("Dst mac : [");
	for(int i=0;i<6;i++) {
	printf("%02x", ep->ether_dhost[i]);
	if(i!=5) printf(":");}
	printf("]\n");

      
	iph = (struct libnet_ipv4_hdr *)packet;
	printf("\n***** Ip header *****\n");
	printf("Src ip : %s\n", inet_ntoa(iph->ip_src));
	printf("Dst ip : %s\n", inet_ntoa(iph->ip_dst));


	tcph = (struct libnet_tcp_hdr *)(packet + iph->ip_hl * 4);
	printf("\n***** Tcp header *****\n");
	printf("Src Port : %d\n" , ntohs(tcph->th_sport));
	printf("Dst Port : %d\n" , ntohs(tcph->th_dport));

	printf("\n\n\n\n\n\n\n\n\n\n\n\n\n");
    }


int main(int argc, char **argv)
{
    char *dev;     
    char errbuf[PCAP_ERRBUF_SIZE];

    struct pcap_pkthdr hdr;
    pcap_t *pcd;  // packet capture descriptor


    if(argc!=2) {
	printf("usage : %s \"Port 80\"\n", argv[0]);
	return -1;
	}

    dev = pcap_lookupdev(errbuf);
    if (dev == NULL)
    {
        printf("%s\n", errbuf);
        exit(1);
    }
    printf("Device : %s\n", dev);


    pcd = pcap_open_live(dev, 4096, 1, 1000, errbuf);
    if (pcd == NULL)
    {
        printf("%s\n", errbuf);
        exit(1);
    }

    pcap_loop(pcd, 0, callback, NULL);
}


