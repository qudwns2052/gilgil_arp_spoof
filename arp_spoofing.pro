TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap
SOURCES += \
        arp_infection.cpp \
        arp_relay.cpp \
        get_my_info.cpp \
        main.cpp

HEADERS += \
    arp_infection.h \
    arp_relay.h \
    get_my_info.h \
    include.h \
    protocol_structure.h
