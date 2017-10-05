#ifndef IEEE80211_H
#define IEEE80211_H
#include <stdint.h>

#define IEEE80211_ADDR_LEN 6

typedef struct ieee80211_radiotap_header {
    // header length = 36

    uint8_t revision;
    uint8_t pad;
    uint16_t length; /* entire length */
    uint8_t present_flags[8]; /* fields present */
    uint8_t zero[4]; // 0 4byte

    uint8_t mac_timestamp[8];
    uint8_t flags;
    uint8_t data_rate; /* in .5 Mb/s units */
    uint8_t channel_frequency1;
    uint8_t channel_frequency2;
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
    uint8_t ssid[32]; // change

}WIRELESS_LAN;

typedef struct ieee80211_wireless_LAN2 {

    uint8_t tag_number;
    uint8_t tag_length;
    uint8_t supported_rates[8];
    uint8_t ds_number;
    uint8_t ds_length;
    uint8_t channel;

}WIRELESS_LAN2;

typedef struct ieee80211_wireless_LAN_probe {
    uint8_t tag_number;
    uint8_t tag_length;
    uint8_t ssid[30];

}WIRELESS_LAN_PROBE;

typedef struct ieee80211_Qos_Data {

    uint8_t type;
    uint8_t frame_control_field;
    uint16_t duration;
    uint8_t receiver_address[6];
    uint8_t transmitter_address[6]; // Station
    uint8_t destination_address[6];
    uint16_t seq;

}QOS_DATA;

typedef struct ieee80211_data {

    uint8_t type;
    uint8_t frame_control_field;
    uint16_t duration;
    uint8_t receiver_address[6];
    uint8_t transmitter_address[6]; // Station
    uint8_t source_address[6];
    uint16_t seq;

}DATA;

typedef struct ieee80211_block_ack {

    uint16_t type;
    uint16_t duration;
    uint8_t receiver_address[6];
    uint8_t transmitter_address[6];

}BLOCK_ACK;

typedef struct ieee80211_probe_request {

    uint8_t type;
    uint8_t control_field;
    uint16_t duration;
    uint8_t receiver_address[6];
    uint8_t transmitter_address[6];
    uint8_t bssid[6];

}PROBE_REQUEST;

typedef struct ieee80211_null_function {

    uint16_t type;
    uint16_t duration;
    uint8_t receiver_address[6];
    uint8_t transmitter_address[6];
    uint8_t destination_address[6];
    uint8_t bssid[6];
    uint8_t station_address[6];

}NULL_FUNCTION;

#endif // IEEE80211_H



