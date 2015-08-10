CONFIG   += c++11
QT       += widgets

TARGET = hungry-sniffer-options
TEMPLATE = lib

QMAKE_LFLAGS_RELEASE += -s -flto -Bsymbolic-functions -fno-exceptions -fno-rtti
QMAKE_CXXFLAGS_RELEASE += -flto -Bsymbolic-functions -fno-exceptions -fno-rtti

SOURCES += \
    call.cpp \
    resolve_hostname.cpp \
    stats_ips.cpp

unix: SOURCES += \
    arpspoof.cpp \
    portredirect.cpp

HEADERS +=\
    options.h \
    stats_ips.h

INCLUDEPATH += $$PWD/../util

FORMS +=


win32: LIBS += -lws2_32
