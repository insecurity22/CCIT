#include <string.h>
#include "stationinfo.h"

StationInfo::StationInfo()
{
}

StationInfo::StationInfo(uint8_t packet) {
    initStation();
    if(packet==0x40) { // probe
        frames += 1;
    }
}

void StationInfo::initStation() {
    memset(bssid, NULL, 6);
    memset(probe, NULL, sizeof(probe));
    frames = 0;
}

