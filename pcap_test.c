#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <pcap.h>
#include <errno.h>
#include <arpa/inet.h>

#define ETHER_ADDR_LEN 6
#define NONPROMISCUOUS 0 // <-> 1


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

	printf("\n*****layer 2: ethernet *****\n");
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
	printf("\n*****layer 3: ip header *****\n");
	printf("Src ip : %s\n", inet_ntoa(iph->ip_src));
	printf("Dst ip : %s\n", inet_ntoa(iph->ip_dst));


	tcph = (struct libnet_tcp_hdr *)(packet + iph->ip_hl * 4);
	printf("\n*****layer 4: tcp header *****\n");
	printf("Src Port : %d\n" , ntohs(tcph->th_sport));
	printf("Dst Port : %d\n" , ntohs(tcph->th_dport));

	printf("\n\n\n\n\n\n\n\n\n\n\n\n\n");
    }


int main(int argc, char **argv)
{

    int ret;

    char *dev;    
    char *net;    
    char *mask;  
    char errbuf[PCAP_ERRBUF_SIZE];

    bpf_u_int32 netp;
    bpf_u_int32 maskp;

    struct pcap_pkthdr hdr;
    struct in_addr net_addr, mask_addr;

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


    ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);
    if (ret == -1)
    {
        printf("%s\n", errbuf);
        exit(1);
    }


    net_addr.s_addr = netp;
    net = inet_ntoa(net_addr);
    printf("Network : %s\n", net);

    mask_addr.s_addr = maskp;
    mask = inet_ntoa(mask_addr);

    printf("Subnet Mask : %s\n", mask);
    printf("=======================\n");


    pcd = pcap_open_live(dev, 4096, NONPROMISCUOUS, -1, errbuf);
    if (pcd == NULL)
    {
        printf("%s\n", errbuf);
        exit(1);
    }

    pcap_loop(pcd, atoi(argv[1]), callback, NULL);
}


