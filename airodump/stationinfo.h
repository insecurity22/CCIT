#ifndef STATIONINFO_H
#define STATIONINFO_H
#include "mac.h"


class StationInfo
{
public:
    Mac bssid;
    int lost;
    int frames;
    uint8_t probe[30];

    StationInfo();
    StationInfo(uint8_t packet);
    void initStation();
};

#endif // STATIONINFO_H


