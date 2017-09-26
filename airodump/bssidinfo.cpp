#include <iostream>
#include <string.h>
#include <netinet/in.h>
#include "bssidinfo.h"
#include "mac.h"
using namespace std;

BssidInfo::BssidInfo() {

}

BssidInfo::BssidInfo(uint8_t packet) {
    initBssid();
    switch(packet) { // framehdr->type
        case 0x80: // beacons
            beacons += 1;
            break;
        case 0x08: // data
            data += 1;
            break;
        default:
            break;
    }
}

void BssidInfo::initBssid() {
    beacons = 0;
    data = 0;
}
