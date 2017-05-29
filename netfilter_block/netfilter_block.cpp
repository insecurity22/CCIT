#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <iostream>
#include <string>
#include <regex>
#include <linux/types.h>
#include <linux/netfilter.h> /* for NF_ACCEPT */
#include <libnetfilter_queue/libnetfilter_queue.h>
using namespace std;

static u_int32_t print_pkt(struct nfq_data *tb) // tb = packet data handle
{
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph; // Packet header
    struct nfqnl_msg_packet_hw *hwph; // Get hardware address
    struct ip *iph;
    struct tcphdr *tcph;
    u_int32_t mark, ifi;
    int ret;
    unsigned char *data;

    ph = nfq_get_msg_packet_hdr(tb);
    if(ph) {
        id = ntohl(ph->packet_id);
        printf("hw_protocol=0x%04x hook=%u id=%u ",
            ntohs(ph->hw_protocol), ph->hook, id);
    }

    hwph = nfq_get_packet_hw(tb);
    if(hwph) {
        int i, hlen = ntohs(hwph->hw_addrlen);

        printf("hw_src_addr=");
        for(i = 0; i < hlen - 1; i++)
            printf("%02x:", hwph->hw_addr[i]);
        printf("%02x ", hwph->hw_addr[hlen - 1]);
    }

    // Filter mark
    mark = nfq_get_nfmark(tb);
    if(mark) printf("mark=%u ", mark);

    // Device to receive packet
    ifi = nfq_get_indev(tb);
    if(ifi) printf("indev=%u ", ifi);

    // Device to sending packet
    ifi = nfq_get_outdev(tb);
    if(ifi) printf("outdev=%u ", ifi);

    // Get physical device's index to receive packet
    ifi = nfq_get_physindev(tb);
    if(ifi) printf("physindev=%u ", ifi);

    // Get physical device to print packet
    ifi = nfq_get_physoutdev(tb);
    if(ifi) printf("physoutdev=%u ", ifi);

    // Get payload : IP start
    ret = nfq_get_payload(tb, &data);
    if(ret > 0) {

        iph = (struct ip*)data;

        if(iph->ip_p == IPPROTO_TCP) {

            data += (iph->ip_hl * 4);
            tcph = (struct tcphdr *)data;

            int cnt = 0;
            printf("\n<TCP header>\n");
            printf("Src Port : %d\n", ntohs(tcph->th_sport));
            printf("Dst Port : %d\n", ntohs(tcph->th_dport));
            while(1) {
                if((cnt % 16) == 0) printf("\n");
                if(cnt == 20) break;

                printf("%02x ", data[cnt]);
                cnt++;
            }
            printf("\n\n");


            cnt = 0;
            int i = 0;
            string savedata;
            printf("TCP data\n");
            char block[] = "Host: www.naver.com\r\n";

            while(1) {
                if(cnt == 50) break;

               /* if ((data[cnt] == 'H' && data[cnt + 1] == 'o' && data[cnt + 2] == 's' && data[cnt + 3] == 't')) {
                      for (int i = 0; i<26; i++) {
                         printf("%c", data[cnt + i]);
                       if (data[cnt + i] == 0x000d && data[cnt + i + 1] == 0x000a) break;
                      }
                } */

                savedata = data[cnt];

                regex re("Host: ([^\n])*");
                smatch m;
                regex_search(data[cnt], m, re);

                cnt++;
            }

                cout << m[0];
                if(regex_search(savedata, m, re)) {
                        if(m[i] == block[i]) {
                            struct nfq_q_handle *qh;

                            nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
                            printf("URL BLOCK");
                        }

                }


        }
        else printf("\nNone tcp packet.\n");


    }

    fputc('\n', stdout);

    return id;
}


static int callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
struct nfq_data *packet_data_handle, void *data)
{
    u_int32_t id = print_pkt(packet_data_handle);

    printf("Entering callback\n");

    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL); // Judge packet
}

int main(int argc, char **argv)
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__((aligned));

    printf("opening library handle\n");
    h = nfq_open(); // open nfqueue handler, get netfilter handle
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) { // unbind
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) { // bind handle at the protocol family
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h, 0, &callback, NULL); // Create new queue handle
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\sn");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) { // Set packet date size for copy
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
        printf("pkt received\n");
        nfq_handle_packet(h, buf, rv); // Processing received packet
    }

    printf("Unbinding from queue 0\n");
    nfq_destroy_queue(qh); // Remove queue handle

    printf("Closing library handle\n");
    nfq_close(h);

    exit(0);
}


