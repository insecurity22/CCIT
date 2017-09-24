#include <iostream>
#include <string.h>
#include <netinet/in.h>
#include "bssidinfo.h"
#include "mac.h"
using namespace std;

BssidInfo::BssidInfo() {

}

void BssidInfo::initBssid() {
    beacons = 0;
    data = 0;
}

void BssidInfo::getBssidInfo(uint8_t _type, uint8_t _chPacket, unsigned char *_essidPacket) {

    if(_type == ntohs(0x0008)) {
        beacons += 1;
    }
    if(_type == ntohs(0x0020)) {
        data += 1;
    }
    channel = _chPacket;
    memcpy(essid, _essidPacket, sizeof(_essidPacket));

}

//void BssidInfo::saveMac(Mac mac, unsigned char *_packet) {

//}


//void BssidInfo::printBssidInfo() {

//    cout << mac << "\t" << beacons << "\t" << data << "\t"
//         << channel << "\t" << essid << endl;
//}
