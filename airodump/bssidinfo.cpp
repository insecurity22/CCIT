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

int BssidInfo::AddBeacons() {

    return beacons += 1;
}

int BssidInfo::AddData() {

    return data += 1;
}

//void BssidInfo::saveMac(Mac mac, unsigned char *_packet) {

//}


//void BssidInfo::printBssidInfo() {

//    cout << mac << "\t" << beacons << "\t" << data << "\t"
//         << channel << "\t" << essid << endl;
//}


