#include <string.h>
#include "stationinfo.h"

StationInfo::StationInfo()
{

}

StationInfo::StationInfo(uint8_t packet) {
    initStation();
    switch(packet) { // framehdr->type
        case 0x08: // probe
            frames += 1;
            break;
    }
}

void StationInfo::initStation() {
    lost = 0;
    frames = 0;
//    memset(bssid.mac_address, NULL, 6);
    memset(probe, NULL, sizeof(probe));
}

