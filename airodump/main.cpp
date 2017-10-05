#include <iostream>
#include <iomanip>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <pcap.h>
#include <unistd.h>
#include <map>
#include "mac.h"
#include "ieee80211.h"
#include "bssidinfo.h"
#include "stationinfo.h"

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

    int res;
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    const unsigned char *packet;
    uint8_t broadcast[6];
    pcap_t *pcd; // packet capture descriptor

    RADIOTAP *radiotaphdr; // Radiotap Header
    BEACON_FRAME *framehdr; // 802.11 Beacon frame
    WIRELESS_LAN *wirelesshdr;
    WIRELESS_LAN2 *wirelesshdr2;
    PKTHDR *pheader;

    PROBE_REQUEST *probehdr;
    BLOCK_ACK *blockhdr;
    QOS_DATA *qoshdr;
    REQUEST_TO_SEND *requestsendhdr;
    WIRELESS_LAN_PROBE *wirelesshdr_probe;
    NULL_FUNCTION *nullfunctionhdr;

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

    map<Mac, BssidInfo> APMap;
    map<Mac, BssidInfo>::iterator iter;

    map<Mac, StationInfo> StationMap;
    map<Mac, StationInfo>::iterator iter2;

    BssidInfo *APInfo;
    StationInfo *StationClass;
    memset(broadcast, 0xff, 6);

    while((res = pcap_next_ex(pcd, &pheader, &packet)) >= 0) {

        if(res == 0) continue;
        if(res < 0) {
            cout << "Error reading the packets" << pcap_geterr(pcd);
            return -1;
        }

        system("clear");
        sleep(0.95);
        printTime();

        radiotaphdr = (RADIOTAP *)packet;
        packet += radiotaphdr->length;

        framehdr = (BEACON_FRAME *)packet;
        probehdr = (PROBE_REQUEST *)packet;
        blockhdr = (BLOCK_ACK *)packet;
        qoshdr = (QOS_DATA *)packet;
        nullfunctionhdr = (NULL_FUNCTION *)packet;
        packet += sizeof(BEACON_FRAME *) + 16; // because destination, source address, and seq

        wirelesshdr = (WIRELESS_LAN *)packet;
        wirelesshdr_probe = (WIRELESS_LAN_PROBE *)packet;
        packet += sizeof(WIRELESS_LAN *) + 6 + wirelesshdr->ssid_length; // supported rate, ds

        wirelesshdr2 = (WIRELESS_LAN2 *)packet;


        // TOP, BSSID
        Mac bssidMac;
        if(framehdr->type == 0x80) { // beacons
            memcpy(bssidMac.mac_address, framehdr->bssid, 6); // BSSID
        }

        // BOTTOM, STATION
        Mac stationMac;
        if(probehdr->type == 0x88) { // Qos data
            if(probehdr->control_field == 0x41) memcpy(stationMac.mac_address, qoshdr->transmitter_address, 6);
            else if(probehdr->control_field == 0x42) memcpy(stationMac.mac_address, qoshdr->receiver_address, 6);
        }
        if(probehdr->type == 0x48) { // Null function
            memcpy(stationMac.mac_address, nullfunctionhdr->transmitter_address, 6);
        }
        if(probehdr->type == 0x40) { // Probe Request, broadcast
            memcpy(stationMac.mac_address, probehdr->transmitter_address, 6);
        }

        // ***************** TOP *****************
        // If the mac exist in the map
        if((iter=APMap.find(bssidMac)) != APMap.end()) {
            switch (framehdr->type) {
            case 0x80: // beacons
                iter->second.beacons += 1;
                break;
            case 0x08: // data
                iter->second.data += 1;
                break;
            }
        }
        else { // Add new mac
            if(framehdr->type==0x80) { // beacons
                APInfo = new BssidInfo(framehdr->type); // + 1
                memcpy(APInfo->essid, wirelesshdr->ssid, wirelesshdr->ssid_length); // ESSID
                APInfo->channel = wirelesshdr2->channel;
            }

            if(framehdr->type==0x08) { // data
                APInfo = new BssidInfo(framehdr->type); // + 1
//                memset(APInfo->essid, NULL, sizeof(APInfo->essid));
//                APInfo->channel = radiotaphdr->channel_frequency1;
            }
            APMap.insert(pair<Mac, BssidInfo>(bssidMac, *APInfo));
       }

        // ***************** BOTTOM *****************
        // If the mac exist in the map
        if((iter2=StationMap.find(stationMac)) != StationMap.end()) {
            switch (probehdr->type) {
            case 0x40: // probe
                iter2->second.frames += 1;
                break;
            }
        }
        else { // Add new mac
            switch (probehdr->type) {
            // STATION
            case 0x08: // Data
                iter2->second.frames += 1;
                break;
            case 0x88: // Qos Data
                StationClass = new StationInfo(probehdr->type);
                if(qoshdr->frame_control_field == 0x41) memcpy(StationClass->bssid, qoshdr->receiver_address, 6);
                else if(qoshdr->frame_control_field == 0x42) memcpy(StationClass->bssid, qoshdr->transmitter_address, 6);
                StationMap.insert(pair<Mac, StationInfo>(stationMac, *StationClass));
                break;
            case 0x48: // Null function
                StationClass = new StationInfo(probehdr->type);
                memcpy(stationMac.mac_address, nullfunctionhdr->transmitter_address, 6);
                memcpy(StationClass->bssid, nullfunctionhdr->receiver_address, 6);
                StationMap.insert(pair<Mac, StationInfo>(stationMac, *StationClass));
                break;
            case 0x40: // Probe request packet
                StationClass = new StationInfo(probehdr->type);
                memcpy(StationClass->bssid, probehdr->receiver_address, 6); // BSSID
                memcpy(StationClass->probe, wirelesshdr_probe->ssid, wirelesshdr_probe->tag_length); // ESSID PROBE
                StationMap.insert(pair<Mac, StationInfo>(stationMac, *StationClass)); // Make map
                break;
            }
          }

        // ***************** PRINT TOP *****************
        cout << endl << " BSSID\t\t\tBeacons\t   #Data\tCH\tESSID" << endl << endl;
        // Print mac and APInfo
        for(iter=APMap.begin(); iter!=APMap.end(); ++iter) {
            printMac((uint8_t *)iter->first.mac_address, 6);
            cout << "\t" << dec
                 << (int)iter->second.beacons << "\t   "
                 << (int)iter->second.data << "\t\t"
                 << (int)iter->second.channel << "\t"
                 << iter->second.essid << endl;
        }

        // ***************** PRINT BOTTOM *****************
        cout << endl << " BSSID\t\t\tSTATION\t\t\tFrames\tProbe" << endl;
        // Print mac and StationInfo
        for(iter2=StationMap.begin(); iter2!=StationMap.end(); ++iter2) {
            if(memcmp(iter2->second.bssid, broadcast, 6)==0) {
                cout << " (not associated) ";
            }
            else {
                printMac((uint8_t *)iter2->second.bssid, 6); // Bssid
            }
            cout << "     ";
            printMac((uint8_t *)iter2->first.mac_address, 6); // Station
            cout << "\t" << dec
                 << iter2->second.frames << "\t"
                 << iter2->second.probe << endl;
        }

    }

    delete APInfo;
    delete StationClass;

    return 0;
}





