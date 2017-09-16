#include <iostream>
#include <iomanip>
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
#include <pcap.h>
#include <map>

using namespace std;

#define IEEE80211_ADDR_LEN 6

int six = 0, inc = 1, first = 0;

void printTime() {
    struct tm *curr_tm; // show time to struct
    time_t curr_time;
    curr_time = time(NULL);
    curr_tm = localtime(&curr_time); // standard local time

    cout << "[ " << curr_tm->tm_year + 1900 << "-" <<
            curr_tm->tm_mon + 1 << "-" <<
            curr_tm->tm_mday + 1;

    cout << " " << curr_tm->tm_hour + 4 << ":" <<
            curr_tm->tm_min << endl;
}

void printBssid() {

}

int cmpMax(map<int, int>* bssid, map<int, int>::iterator iter, uint8_t *transmitter_addr, int num) {

    int cmpsame, addr = 0;
    // The max is same = 1
    // The max isn't same = 2

    for(int i=num; i<num+6; i++) {
        iter = (*bssid).find(i);
        // 0 - 6
        // compare original value and current value
        if((int)iter->second == (int)transmitter_addr[addr]) cmpsame = 1;
        else cmpsame = 2;
        addr++;
    }

    return cmpsame;
}

void saveBssid(map<int, int>* bssid, map<int, int>::iterator iter, uint8_t *transmitter_addr, int num) {
    // have to use swap function
    int addr = 0;

    cout << " ";
    for(int i=num; i<num+6; i++) {
        (*bssid).insert(map<int, int>::value_type(i, (int)transmitter_addr[addr]));
        addr++;
    }

    for(int i=num; i<num+6; i++) {
        iter = (*bssid).find(i);
        cout << setfill('0') << setw(2) << hex << (int)iter->second;
        if(i!=(num-1+6)) cout << ":";
    }
    cout << "\t";
}

int onlyPrint(map<int, int>* bssid, map<int, int>::iterator iter, int num) {

    cout << " ";
    for(int i=num; i<num+6; i++) {
        iter = (*bssid).find(i);
        cout << setfill('0') << setw(2) << hex << (int)iter->second;
        if(i!=(num-1+6)) cout << ":";
    }
    cout << "\t";

    return num;
}

void getpwr(map<int, int>* pwr, map<int, int>::iterator iter, u_int8_t pwrpacket, int num) {

    (*pwr).insert(map<int, int>::value_type(num, (int)pwrpacket));
    iter = (*pwr).find(num);

    cout << "-" << dec << 256-(int)iter->second << "\t";

}

int checkmaclocation(map<int, int>* bssid, map<int, int>::iterator iter, uint8_t *transmitter_addr, int cmp1) {

    int value = 0, addr = 0, save = 0;
    if(cmp1==0) {
        for(int i=0; i<6; i++) {
            iter = (*bssid).find(i);
            if((int)iter->second == (int)transmitter_addr[addr]) {
                if(cmp1%6==0) save = cmp1;
                value = save;
                addr++;
            }
        }
    }
    else {
        for(int i=cmp1; i<cmp1+6; i++) {
            iter = (*bssid).find(i);
            if((int)iter->second == (int)transmitter_addr[addr]) {
                if(cmp1%6==0) save = cmp1;
                value = save;
                addr++;
            }
        }
    }

    return value;
}


void getbeacons(uint8_t type, int beacon_frame_count, map<int, int>* Qospacket, map<int, int>::iterator iter, int num) {
    // When I get Qos packet
    // If there is same mac, the beacon_frame_count increase in the map

    iter = (*Qospacket).find(num);
    if(type == 0x0080) {
        beacon_frame_count += 1;
        (*Qospacket).insert(map<int, int>::value_type(num, beacon_frame_count));

        cout << dec << (int)iter->second << "\t\t";
    }
    else {
        cout << dec << (int)iter->second << "\t\t";
    };

}

void findmacnum(map<int, int>* mac, map<int, int>::iterator iter, u_int8_t pwrpacket, int num) {
    iter = (*mac).find(num/6);

    for(int i=0; i<num; i++) {

    }


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


struct ieee80211_beacon_frame {

    uint8_t i_type;
    uint8_t fcf; // type+fcf = fcf
    uint16_t i_dur;
    uint8_t i_receiver_addr[IEEE80211_ADDR_LEN];
    uint8_t i_transmitter_addr[IEEE80211_ADDR_LEN];
    uint8_t i_bssid[IEEE80211_ADDR_LEN];
    uint8_t i_seq[2];

    // ieee80211_wireless_LAN
    int64_t timestamp;
    u_int16_t beacon_interval;
    u_int16_t capabilities;
    u_int8_t ssid_number;
    u_int8_t ssid_length;
    u_int8_t ssid[30]; // change
};

struct save_info {
      u_int8_t bssid[6];
      u_int8_t ssi_signal;
      int beacon_count;
      int data_count;
};

struct ieee80211_wireless_LAN2 {
    u_int8_t tag_number;
    u_int8_t tag_length;
    u_int8_t supported_rates[8];
    u_int8_t ds_number;
    u_int8_t ds_length;
    u_int8_t channel;
};

int main(int argc, char *argv[]) {

    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcd; // packet capture descriptor
    int res, same, totalpacket, maclocation = 0; // totalpacket : for print exclude bssid
    int beacon_frame_count = 0, data_count = 0;
    struct ieee80211_radiotap_header *radiotaphdr; // Radiotap Header
    struct ieee80211_beacon_frame *framehdr; // 802.11 Beacon frame
    struct ieee80211_wireless_LAN2 *wirelesshdr;
    struct pcap_pkthdr *pheader;
    const unsigned char *packet;
    struct save_info *si;

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

    printTime();

    map<int, int>* bssid = new map<int, int>();
    map<int, int>::iterator iter;

    map<int, int>* pwr = new map<int, int>();

    map<int, int>* Qospacket = new map<int, int>();



    while((res = pcap_next_ex(pcd, &pheader, &packet)) >= 0) {

        if(res == 0) continue;
        if(res < 0) {
            cout << "Error reading the packets" << pcap_geterr(pcd);
            return -1;
        }

        cout << " BSSID\t\t\tPWR\tBeacons\t#Data\tCH  MB  ENC  CIPHER AUTH ESSID" << endl;

        radiotaphdr = (struct ieee80211_radiotap_header *)packet;
        packet += radiotaphdr->it_len;
        framehdr = (struct ieee80211_beacon_frame *)packet;

        // BSSID
        if(first == 0) {
            // It only starts first
            saveBssid(bssid, iter, framehdr->i_transmitter_addr, 0); // 0 - 6, save original
            getpwr(pwr, iter, radiotaphdr->ssi_signal, 0);
            getbeacons(framehdr->i_type, beacon_frame_count, Qospacket, iter, inc);
            first = 1;
        }
        else {
            int cmp = 0, cmp1 = 0;
            for(int i=0; i<inc; i++) {
                // compare saved 0 - 6 max and current max
                same = cmpMax(bssid, iter, framehdr->i_transmitter_addr, cmp);
                cmp += 6;


                if(same == 1) break;
            }
            if(same == 1) {
                // If it same, only print
                for(int i=0; i<inc; i++) {
                    onlyPrint(bssid, iter, cmp1); // print original mac

                    maclocation = checkmaclocation(bssid, iter, framehdr->i_transmitter_addr, cmp1);
                    getpwr(pwr, iter, radiotaphdr->ssi_signal, maclocation);

                    getbeacons(framehdr->i_type, beacon_frame_count, Qospacket, iter, inc);

                    cmp1 += 6;
                }
            }
            else if(same == 2) {
                // not same
                for(int i=0; i<1; i++) {
                    saveBssid(bssid, iter, framehdr->i_transmitter_addr, six+6);

                    maclocation = checkmaclocation(bssid, iter, framehdr->i_transmitter_addr, six+6);
                    getpwr(pwr, iter, radiotaphdr->ssi_signal, maclocation);

                    getbeacons(framehdr->i_type, beacon_frame_count, Qospacket, iter, inc);
                }
                six += 6;
                // If the mac address added,  the inc increase one.
                inc += 1;
            }
        }
        totalpacket += 1;

        // #Data
        if(framehdr->i_type == 0x0020) {
            data_count += 1;
            cout << data_count << "\t";
        }
        else { cout << data_count << "\t";}


        wirelesshdr = (struct ieee80211_wireless_LAN2 *)packet + sizeof(struct ieee80211_beacon_frame *)
                - sizeof(framehdr->ssid) + framehdr->ssid_length;
      //  packet += + ;

        // CH
        if(framehdr->i_type == 0x0080) {
            cout << setfill('0') << setw(2) << hex << (int)wirelesshdr->tag_number
                 << setfill('0') << setw(2) << hex << (int)wirelesshdr->tag_length <<
                   setfill('0') << setw(2) << hex <<  (int)wirelesshdr->supported_rates[0];
    }
        else { }


        cout << endl;
        // cout << hex << (int)framehdr->i_type;

        // ESSID

        if(framehdr->i_type == 0x0080) {
             for(int i=0; i<framehdr->ssid_length; i++) {
               cout << framehdr->ssid[i];
             }
        }

        cout << endl << endl << endl;

    }

    cout << endl;
    return 0;
}

