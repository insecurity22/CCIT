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
    void initBssid();
    int AddBeacons();
    int AddData();
};

#endif // BSSIDINFO_H
