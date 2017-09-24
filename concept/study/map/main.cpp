#include <iostream>
#include <map>
#include "people.h"
#include <string.h>

using namespace std;

int main(int argc, char *argv[])
{

    // (1)
    //    map<char, int> num;
    //    map<char, int>::iterator iter;
    //    num.insert(pair<char, int>('a', 1));
    //    num.insert(pair<char, int>('b', 2));
    //    num.insert(pair<char, int>('c', 100));
    //    num.insert(pair<char, int>('d', 20));

    //    if((iter = num.find('d')) != num.end()) {
    //        cout << iter->second;
    //    }


    // (2)
    //    map<char, People> pe;
    //    map<char, People>::iterator iter1;

    //    People bokyoung;
    //    bokyoung.age = 22;
    //    strcpy(bokyoung.name, "bo");
    //    bokyoung.height = 162;
    //    bokyoung.weight = 30;
    //    pe.insert(pair<char, People>('b', bokyoung));


    //    People info;
    //    info.data = 10;
    //    info.channel = 11;
    //    info.beacons = 200;
    //    strcpy(info.essid, "gildong");
    //    pe.insert(pair<char, People>('h', info));


    //    cout << bokyoung.age;
    //    if((iter1 = pe.find('b')) != pe.end()) {
    //        cout << iter1->second.age <<" "<< iter1->second.height << " "<<
    //                iter1->second.name <<" "<<iter1->second.weight;
    //    }

    // *** If same max is exist ... <-- this part
    // *** Never mind compare. will work operator.
    //    if((iter1 = pe.find('h')) != pe.end()) {  
    //        cout << iter1->second.data << " " << iter1->second.channel << " " <<
    //                iter1->second.beacons << " " << iter1->second.essid << " ";
    //    }
    //    else {

    //        info.data = 10;
    //        info.channel = 11;
    //        info.beacons = 200;
    //        strcpy(info.essid, "bb");

    //        pe.insert(pair<char, People>('b', info));
    //    }



    // (3)
    // ( wrong ) - Because compare all mac
    //    int num;
    //    uint8_t origin[6];
    //    uint8_t cmpbssid[6];
    //    for(int i=0; i<6; i++) {
    //        if(origin[i] == cmpbssid[i]) num = 1;
    //        else num = 2;
    //    }



    // (4)
    // ( correct ) - use like this
    //    struct BSSID {
    //        uint8_t mac[6];

    //        bool operator <( const BSSID &_bssid ) const
    //        {
    //           return tie(mac[0], mac[1], mac[2],mac[3],mac[4],mac[5])<tie(_bssid.mac[0],_bssid.mac[1],_bssid.mac[2],_bssid.mac[3],_bssid.mac[4],_bssid.mac[5]);
    //        }
    //    };
    // If you write _bssid[0], It means "struct BSSID[0]"
    // No match for 'operator[]' ...
    // _bssid = point class, and the computer can't know BSSID class.
    // So you have to use _bssid.mac[0]


    //    map<BSSID, People> pe;
    //    map<BSSID, People>::iterator iter1;

    //    BSSID h;

    //    if((iter1 = pe.find(h)) != pe.end()) {
    //        cout << "exist";
    //    }

    return 0;
}

