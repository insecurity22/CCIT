#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <pcap.h>
#include <errno.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

struct ip *iph;
struct tcphdr *tcph;
void eth_cal(unsigned char *packet) {
    for(int i=0; i<6; i++) {
        printf("%02x", packet[i]);
        if(i!=5) printf(":");
    }
    printf("] \n");
}

void callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet) {

    struct ether_header *ep;
    unsigned short ether_type;
    int cnt = 0;

    ep = (struct ether_header *)packet;
    ether_type = ntohs(ep->ether_type);

    printf("\n*---- Ethernet ----*\n");
    printf("Src mac : [");
    eth_cal(ep->ether_shost);

    printf("Dst mac : [");
    eth_cal(ep->ether_dhost);

    packet += sizeof(struct ether_header);
    iph = (struct ip *)packet;

    printf("\n*---- Ip header ----*\n");
    printf("Src ip : %s\n", inet_ntoa(iph->ip_src));
    printf("Dst ip : %s\n", inet_ntoa(iph->ip_dst));

    packet += (iph->ip_hl * 4);
    tcph = (struct tcphdr *)(packet + iph->ip_hl * 4);

    printf("\n*---- Tcp header ----*\n");
    printf("Src Port : %d\n" , ntohs(tcph->th_sport));
    printf("Dst Port : %d\n" , ntohs(tcph->th_dport));

    printf("\n*---- Tcp data ----*\n");
    for(int i=0; i<20; i++) {
        printf("%02x ", packet[i]);
        cnt++;
        if((cnt%10)==0) {
            printf("\n");
        }
    }
    printf("\n\n\n\n");
}

int main(int argc, char **argv)
{
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcd;  // packet capture descriptor

    if(argc!=2) {
        printf("usage : %s \"port 80\"\n", argv[0]);
        return -1;
    }

    dev = pcap_lookupdev(errbuf);
    if (dev == NULL)
    {
        printf("%s\n", errbuf);
        return -1;
    }
    printf("Device : %s\n", dev);

    pcd = pcap_open_live(dev, 4096, 1, 1000, errbuf);
    if (pcd == NULL)
    {
        printf("%s\n", errbuf);
        return -1;
    }
    pcap_loop(pcd, 0, callback, NULL);
}
