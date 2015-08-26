CONFIG   += c++11
QT       += widgets

TARGET = hungry-sniffer-options
TEMPLATE = lib

include(../common.pri)

*-g++* {
    QMAKE_CXXFLAGS_RELEASE += -flto -Bsymbolic-functions -fno-exceptions -fno-rtti
    QMAKE_LFLAGS_RELEASE += -s -flto -Bsymbolic-functions -fno-exceptions -fno-rtti
}

*-msvc* {
    QMAKE_CXXFLAGS_RELEASE += /GL
    QMAKE_LFLAGS_RELEASE += /LTCG
}

SOURCES += \
    call.cpp \
    resolve_hostname.cpp \
    stats_ips.cpp \
    stats_length.cpp

unix: SOURCES += \
    arpspoof.cpp \
    portredirect.cpp

HEADERS +=\
    options.h \
    stats_ips.h \
    stats_length.h

INCLUDEPATH += $$PWD/../sdk

FORMS +=


win32: LIBS += -lws2_32
