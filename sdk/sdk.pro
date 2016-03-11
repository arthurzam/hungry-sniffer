CONFIG   += c++11

TARGET = hungry-sniffer-sdk
TEMPLATE = lib

include(../common.pri)

DEFINES += SDK_LIBRARY

*-g++* {
    QMAKE_CXXFLAGS_RELEASE += -flto -fno-exceptions -fno-rtti
    QMAKE_LFLAGS_RELEASE += -flto -fno-exceptions -fno-rtti
}

win32-g++ {
    QMAKE_LFLAGS_RELEASE += -static-libgcc -static-libstdc++
    DEFINES += WIN32
    unset(VERSION)
}

*-msvc* {
    QMAKE_CXXFLAGS_RELEASE += /GL
    QMAKE_LFLAGS_RELEASE += /LTCG
    unset(VERSION)
}

SOURCES += \
    protocol.cpp \
    globals.cpp \
    transport_layer_packet.cpp

HEADERS  += \
    hs_core.h \
    hs_advanced_packets.h \
    hs_prefs.h \
    hs_protocol.h \
    hs_plugin.h \
    hs_stats.h \
    hs_transport_layer_packet.h

unix {
    OTHER_FILES += HungrySniffer.pc

    target.path = $$PREFIX/lib

    headers.path = $$PREFIX/include/HungrySniffer
    headers.files = $$HEADERS

    pc.path = $$PREFIX/lib/pkgconfig/
    pc.files = HungrySniffer.pc

    INSTALLS += headers pc target
}

OTHER_FILES += CMakeLists.txt
