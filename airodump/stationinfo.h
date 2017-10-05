#ifndef STATIONINFO_H
#define STATIONINFO_H
#include "mac.h"


class StationInfo
{
public:
    uint8_t bssid[6];
    int frames;
    uint8_t probe[30];

    StationInfo();
    StationInfo(uint8_t packet);
    void initStation();
};

#endif // STATIONINFO_H


