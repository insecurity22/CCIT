#ifndef IEEE80211_H
#define IEEE80211_H
#include <stdint.h>

#define IEEE80211_ADDR_LEN 6

typedef struct ieee80211_radiotap_header {

    uint8_t revision;
    uint8_t pad;
    uint16_t length; /* entire length */
    uint8_t present_flags[8]; /* fields present */

    uint8_t mac_timestamp[8];
    uint8_t flags;
    uint8_t data_rate; /* in .5 Mb/s units */
    uint16_t channel_frequency;
    uint16_t channel_flags;
    uint8_t ssi_signal;
    uint16_t rx_flags;
    uint8_t ssi_signal2;
    uint8_t antenna;

}RADIOTAP;

typedef struct ieee80211_beacon_frame {

    uint8_t type;
    uint8_t frame_control_field; // type+fcf = fcf
    uint16_t duration;
    uint8_t receiver_addr[IEEE80211_ADDR_LEN];
    uint8_t transmitter_addr[IEEE80211_ADDR_LEN];
    uint8_t bssid[IEEE80211_ADDR_LEN];
    uint8_t seq[2];

}BEACON_FRAME;

typedef struct ieee80211_wireless_LAN {

    uint8_t timestamp[8];
    uint16_t beacon_interval;
    uint16_t capabilities;
    uint8_t ssid_number;
    uint8_t ssid_length;
    uint8_t ssid[30]; // change

}WIRELESS_LAN;

typedef struct ieee80211_wireless_LAN2 {

    uint8_t tag_number;
    uint8_t tag_length;
    uint8_t supported_rates[8];
    uint8_t ds_number;
    uint8_t ds_length;
    uint8_t channel;

}WIRELESS_LAN2;

#endif // IEEE80211_H



