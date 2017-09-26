#ifndef BSSIDINFO_H
#define BSSIDINFO_H
#include <stdint.h>
#include "mac.h"

class BssidInfo
{
public:
    int beacons;
    int data;
    uint8_t channel;
    char essid[30];

    BssidInfo();
    BssidInfo(uint8_t packet);
    void initBssid();
};

#endif // BSSIDINFO_H


