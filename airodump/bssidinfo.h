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
    void getBssidInfo(uint8_t _type, uint8_t _chPacket, unsigned char *_essidPacket);
   // void saveMac(Mac mac, unsigned char *_packet);
};

#endif // BSSIDINFO_H
