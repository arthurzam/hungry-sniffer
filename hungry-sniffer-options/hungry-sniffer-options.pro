CONFIG   += c++11
QT       += widgets

TARGET = hungry-sniffer-options
TEMPLATE = lib

QMAKE_LFLAGS_RELEASE += -s -flto -Bsymbolic-functions -fno-exceptions -fno-rtti
QMAKE_CXXFLAGS_RELEASE += -flto -Bsymbolic-functions -fno-exceptions -fno-rtti

SOURCES += \
    call.cpp \
    arpspoof.cpp \
    portredirect.cpp \
    resolve_hostname.cpp \
    stats_ips.cpp

HEADERS +=\
    Protocol.h \
    options.h \
    stats_ips.h

FORMS +=
