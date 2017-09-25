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
#include "ieee80211.h"
#include "mac.h"
#include "bssidinfo.h"

#define IEEE80211_ADDR_LEN 6
typedef struct pcap_pkthdr PKTHDR;

using namespace std;

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

void printMac(uint8_t *printArr, int length)
{
    cout << " ";
    for(int i=0; i<length; i++)
    {
        cout << setfill('0') << setw(2) << hex << (int)printArr[i];
        if(i!=5) cout<<":";
    }
}

int main(int argc, char *argv[]) {

    int res, add = 1;
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    const unsigned char *packet;
    pcap_t *pcd; // packet capture descriptor

    RADIOTAP *radiotaphdr; // Radiotap Header
    BEACON_FRAME *framehdr; // 802.11 Beacon frame
    WIRELESS_LAN *wirelesshdr;
    WIRELESS_LAN2 *wirelesshdr2;
    PKTHDR *pheader;

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

    map<Mac, BssidInfo> APMap;
    map<Mac, BssidInfo>::iterator iter;

    BssidInfo APInfo;
    APInfo.initBssid();

    while((res = pcap_next_ex(pcd, &pheader, &packet)) >= 0) {

        if(res == 0) continue;
        if(res < 0) {
            cout << "Error reading the packets" << pcap_geterr(pcd);
            return -1;
        }

        radiotaphdr = (RADIOTAP *)packet;
        packet += radiotaphdr->length;
        framehdr = (BEACON_FRAME *)packet;
        packet += sizeof(BEACON_FRAME *) + 16; // To bssid
        wirelesshdr = (WIRELESS_LAN *)packet;
        packet += sizeof(WIRELESS_LAN *);
        wirelesshdr2 = (WIRELESS_LAN2 *)packet;

        cout << endl << " BSSID\t\t\tBeacons\t\t#Data\tCH\tESSID" << endl << endl;

        Mac macaddress;
        memcpy(macaddress.mac_address, framehdr->transmitter_addr, 6); // BSSID

        switch (framehdr->type) {
        case 0x80: // Beacons
            memcpy(APInfo.essid, wirelesshdr->ssid, wirelesshdr->ssid_length); // ESSID
            APInfo.AddBeacons();
            APMap.insert(pair<Mac, BssidInfo>(macaddress, APInfo));

            // iter... use
            //            if((iter=APMap.find(macaddress)) != APMap.end()) {  // exist
            //                iter->second.
            //            }
            break;

        case 0x08: // Data, 0x0020
            APInfo.AddData();
            APMap.insert(pair<Mac, BssidInfo>(macaddress, APInfo));
            break;

        default:
            break;
        }

        for(iter = APMap.begin(); iter != APMap.end(); ++iter) {
            printMac((uint8_t *)iter->first.mac_address, 6);
            cout << hex << "\t"
                 << iter->second.beacons << "\t\t"
                 << iter->second.data << "\t\t"
                 << iter->second.essid << endl;
        }

        cout << endl << " BSSID\t\t\tSTATION\t\tLost\tFrames\tProbe" << endl;

        cout << endl << endl << endl << endl;
    }

    return 0;
}





