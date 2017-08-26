#include <iostream>
#include <pcap.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <fcntl.h>
#include <pthread.h>
#include <termios.h>
#include <time.h>

using namespace std;

#define IEEE80211_ADDR_LEN 6

void PrintTime(struct tm *curr_tm) {

    cout << "[ " << curr_tm->tm_year + 1900 << "-" <<
            curr_tm->tm_mon + 1 << "-" <<
            curr_tm->tm_mday + 1;

    cout << " " << curr_tm->tm_hour + 4 << ":" <<
            curr_tm->tm_min << endl;
}

struct ieee80211_radiotap_header {
    u_int8_t it_version; /* set to 0 */
    u_int8_t it_pad;
    u_int16_t it_len; /* entire length */
    int64_t it_present; /* fields present */
    int64_t mactimestamp;
    u_int8_t flags;
    u_int8_t data_rate; /* in .5 Mb/s units */
    u_int16_t channel_frequency; /* entire length */
    u_int16_t channel_flags;
    u_int8_t ssi_signal;
    u_int16_t rx_flags;
    u_int8_t ssi_signal2;
    u_int8_t antenna;

};

struct ieee80211_hdr {
};

struct ieee80211_beacon_frame {
    uint16_t i_fc;
    uint16_t i_dur;
    uint8_t i_receiver_addr[IEEE80211_ADDR_LEN];
    uint8_t i_transmitter_addr[IEEE80211_ADDR_LEN];
    uint8_t i_bssid[IEEE80211_ADDR_LEN];
    uint8_t i_seq[2];
};

int main(int argc, char *argv[])
{
    time_t curr_time;
    struct tm *curr_tm; // show time to struct

    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcd; // packet capture descriptor
    int res;

    int i=0;
    struct ieee80211_radiotap_header *radiotaphdr; // Radiotap Header
    struct ieee80211_beacon_frame *framehdr; // 802.11 Beacon frame
    struct pcap_pkthdr *pheader;
    const unsigned char *packet;

    if(argc != 2) {
        cout << "usage : " << argv[0] << " interface_name" << endl;
        return -1;
    }

    dev = argv[1];
    pcd = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if(pcd == NULL) {
        cout << "Device " << dev << "can't open : " << errbuf;
        return -1;
    }

    while((res = pcap_next_ex(pcd, &pheader, &packet)) >= 0) {

        if(res == 0) continue;
        if(res < 0) {
            cout << "Error reading the packets" << pcap_geterr(pcd);
            return -1;
        }

        //cout << " BSSID\t\tPWR  Beacons\t#Data, #/s  CH  MB  ENC  CIPHER AUTH ESSID" << endl;

        radiotaphdr = (struct ieee80211_radiotap_header *)packet;
        packet += radiotaphdr->it_len;
        framehdr = (struct ieee80211_beacon_frame *)packet;


        for(int i=0; i<2; i++) {
            cout << hex << (int)framehdr->i_transmitter_addr[i]<<endl;
            if(i!=11) cout << ":";
            i++;
        }

        cout << endl;

    }

    cout << endl;
    return 0;
}
