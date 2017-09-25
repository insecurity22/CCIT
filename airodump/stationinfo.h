#ifndef STATIONINFO_H
#define STATIONINFO_H
#include "mac.h"


class StationInfo
{
    Mac mac;
    Mac station;
    int rate;
    int lost;
    int frames;
    int probe;

public:
    StationInfo();
    void printStationInfo();
};

#endif // STATIONINFO_H


