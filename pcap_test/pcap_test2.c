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

void eth_cal(unsigned char *packet) {
    for (int i = 0; i<6; i++) {
        printf("%02x", packet[i]);
        if (i != 5) printf(":");
    }
    printf("]\n");
}

struct ethhdr *ep;
struct ip *iph;
struct tcphdr *tcph;
int Printf_ethernet(const u_char *packet) {

    ep = (struct ethhdr *)packet;

    printf("\n ***** Ethernet *****\n");
    printf("Src mac : [");
    eth_cal(ep->h_source);

    printf("Dst mac : [");
    eth_cal(ep->h_dest);
}

int Printf_ip(const u_char *packet) {

    iph = (struct ip *)packet;
    unsigned short ether_type;
    ether_type = ntohs(ep->h_proto);

    printf("\n ***** IP *****\n");
    if (ether_type == ETHERTYPE_IP) {
        printf("Src ip : %s\n", inet_ntoa(iph->ip_src));
        printf("Dst ip : %s\n", inet_ntoa(iph->ip_dst));
    }
    else printf("\nNone ip packet.\n");
}

int Printf_tcp(const u_char *packet) {

    tcph = (struct tcphdr *)packet;

    printf("\n ***** Tcp header *****\n");
    if (iph->ip_p == IPPROTO_TCP) {
        printf("Src Port : %d\n", ntohs(tcph->th_sport));
        printf("Dst Port : %d\n", ntohs(tcph->th_dport));
    } else printf("None tcp packet.\n");
}

int Printf_tcp_data(const u_char data[], int len) {

    int cnt = 0;
    printf("\n ***** TCP Data *****");
    while (len--) {
        if ((cnt % 16) == 0) printf("\n");
        if (cnt == 80) break;
        printf("%02x ", data[cnt]);
        cnt++;
    }
    printf("\n\n");
}

int Printf_http_host(const u_char packet[], int len) {

    int cnt = 0;
    printf(" ***** http host ***** \n");
    while (len--){
        cnt++;
        if (cnt == 20) break;
        if ((packet[cnt] == 'h' && packet[cnt + 1] == 'o' && packet[cnt + 2] == 's' && packet[cnt + 3] == 't') ||
            (packet[cnt] == 'H' && packet[cnt + 1] == 'o' && packet[cnt + 2] == 's' && packet[cnt + 3] == 't')) {
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

    int res, len = 0;
    if (argc != 3) {
        printf("usage : %s device_name \"port 80\"", argv[0]); /* "port 80" is filter */
        return -1;
    }

    dev = argv[1];
    if (argv[1] == NULL) {
        printf("%s\n", errbuf);
        exit(1);
    }

    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        printf("Device %s can't get netmask\n", dev);
        net = 0;
        mask = 0;
    }

    pcd = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (pcd == NULL) {
        printf("Device %s can't open : %s\n", dev, errbuf);
        return -1;
    }

    if (pcap_compile(pcd, &filter_protocal, argv[2], 0, net) == -1) {
        printf("Filter \"port %s\" is wrong\n", argv[1]);
        return -1;
    }

    if (pcap_setfilter(pcd, &filter_protocal) == -1) {
        printf("%s Filter can't install %s\n", argv[2], pcap_geterr(pcd));
        return -1;
    }

    while ((res = pcap_next_ex(pcd, &pkthdr, &pkt_data)) >= 0) {
        printf("%d", res);
        if (res == 0); // lost packet
        if (res < 0) {
            printf("Error reading the packets: %s\n", pcap_geterr(pcd));
            return -1;
        }

        Printf_ethernet(pkt_data);

        pkt_data += sizeof(struct ethhdr);
        Printf_ip(pkt_data);

        pkt_data += (iph->ip_hl * 4);
        Printf_tcp(pkt_data);

        pkt_data += (tcph->th_off * 4);
        len = (iph->ip_len) - sizeof(struct ethhdr) - (iph->ip_hl * 4) - (tcph->th_off * 4);
        Printf_tcp_data(pkt_data, len);
        Printf_http_host(pkt_data, len);
        printf("\n\n\n");
    }
}
