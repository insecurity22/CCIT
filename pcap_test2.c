#include <netinet/in.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>


struct ethhdr *ep;
struct ip *iph;
struct tcphdr *tcph;

int Printf_ethernet(const u_char *packet) {

    ep = (struct ethhdr *)packet;

    printf("\n ***** Ethernet *****\n");
    printf("Src mac : [");
    for (int i = 0; i<6; i++) {
        printf("%02x", ep->h_source[i]);
        if (i != 5) printf(":");
    }
    printf("]\n");

    printf("Dst mac : [");
    for (int i = 0; i<6; i++) {
        printf("%02x", ep->h_dest[i]);
        if (i != 5) printf(":");
    }
    printf("]\n");
}


int Printf_ip(const u_char *packet) {

    packet += sizeof(struct ethhdr);
    iph = (struct ip *)packet;

    unsigned short ether_type;
    ether_type = ntohs(ep->h_proto);

    printf("\n ***** IP *****\n");
    if (ether_type == 0x0800) {
        printf("Src ip : %s\n", inet_ntoa(iph->ip_src));
        printf("Dst ip : %s\n", inet_ntoa(iph->ip_dst));
    }
    else printf("\nNone ip packet.\n");
}

int Printf_tcp(const u_char *packet) {

    packet += sizeof(struct ethhdr) + (iph->ip_hl * 4);
    tcph = (struct tcphdr *)packet;


    printf("\n ***** Tcp header *****\n");
    if (iph->ip_p == 0x06) {
        printf("Src Port : %d\n", ntohs(tcph->th_sport));
        printf("Dst Port : %d\n", ntohs(tcph->th_dport));
    }
    else printf("None tcp packet.\n");

}

int Printf_tcp_data(const u_char data[]) {

    struct pcap_pkthdr *pkthdr;

    int len = (pkthdr->len) - sizeof(struct ethhdr) - (iph->ip_hl * 4) - (tcph->th_off);
    int cnt = 0;

    data += sizeof(struct ethhdr) + (iph->ip_hl * 4) + (tcph->th_off * 4);


    printf("\n ***** TCP Data *****");
    while (len--) {

        if ((cnt % 16) == 0) printf("\n");
        if (cnt == 80) break;

        printf("%02x ", data[cnt]);
        cnt++;
    }

    printf("\n\n");

}

int Printf_http_host(const u_char packet[]) {

    struct pcap_pkthdr *pkthdr;
    int cnt = 0, cnt2 = 0;
    int len = (pkthdr->len) - sizeof(struct ethhdr) - (iph->ip_hl * 4) - (tcph->th_off * 4);
    packet += sizeof(struct ethhdr) + (iph->ip_hl * 4) + (tcph->th_off * 4);

    printf(" ***** http host ***** \n");
    while (len--){
        cnt++;
        if (cnt == 20) break;
        if ((packet[cnt] == 0x0048 && packet[cnt + 1] == 0x004f) || (packet[cnt] == 0x0048 && packet[cnt + 1] == 0x006f)) {
            for (int i = 0; i<26; i++) {
                printf("%c", packet[cnt + i]);
                if (packet[cnt + i] == 0x000d && packet[cnt + i + 1] == 0x000a) break;
            }
        }
    }
}


int main(int argc, char **argv) {


    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];

    struct pcap_pkthdr *pkthdr;
    struct bpf_program filter_protocal;

    pcap_t *pcd; // packet capture descriptor
    const u_char *pkt_data;


    bpf_u_int32 net;
    bpf_u_int32 mask;

    int res;



    if (argc != 3) {
        printf("usage : %s device_name \"port 80\"<-- filter_part\n", argv[0]);
        return -1;
    }

    dev = argv[1];
    if (argv[1] == NULL) {
        printf("%s\n", errbuf);
        exit(1);
    }

    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        printf("디바이스 %s의 netmask를 얻을 수 없습니다\n", dev);
        net = 0;
        mask = 0;
    }

    pcd = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (pcd == NULL) {
        printf("장치 %s를 열 수 없습니다 : %s\n", dev, errbuf);
        return -1;
    }

    if (pcap_compile(pcd, &filter_protocal, argv[2], 0, net) == -1) {
        printf("필터 Port %s를 구문 분석할 수 없습니다\n", argv[1]);
        return -1;
    }

    if (pcap_setfilter(pcd, &filter_protocal) == -1) {
        printf("%s 필터를 설치할 수 없습니다. %s\n", argv[2], pcap_geterr(pcd));
        return -1;
    }



    while (res = pcap_next_ex(pcd, &pkthdr, &pkt_data) >= 0){

        if (res < 0)
        {
            printf("Error reading the packets: %s\n", pcap_geterr(pcd));
            return -1;
        }

        Printf_ethernet(pkt_data);
        Printf_ip(pkt_data);
        Printf_tcp(pkt_data);
        Printf_tcp_data(pkt_data);
        Printf_http_host(pkt_data);


        printf("\n\n\n");

    }

}


