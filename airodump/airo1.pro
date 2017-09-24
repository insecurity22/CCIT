TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap

SOURCES += main.cpp \
    mac.cpp \
    bssidinfo.cpp \
    stationinfo.cpp

HEADERS += \
    mac.h \
    ieee80211.h \
    bssidinfo.h \
    stationinfo.h
