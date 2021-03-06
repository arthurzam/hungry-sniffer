TEMPLATE = lib
greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++11

TARGET = hungry-sniffer-protocols
TEMPLATE = lib

include(../common.pri)

*-g++* {
    QMAKE_CXXFLAGS_RELEASE += -flto -fno-exceptions -fno-rtti
    QMAKE_LFLAGS_RELEASE += -s -flto -fno-exceptions -fno-rtti
}

win32-g++ {
    QMAKE_LFLAGS_RELEASE += -static-libgcc -static-libstdc++ -static
    DEFINES += WIN32 Q_CC_MINGW
}

*-msvc* {
    QMAKE_CXXFLAGS_RELEASE += /GL
    QMAKE_LFLAGS_RELEASE += /LTCG
}

win32: DEFINES += Q_OS_WIN
unix:  DEFINES += Q_OS_UNIX

SOURCES += \
  ArpPacket.cpp \
  DNSPacket.cpp \
  ICMPPacket.cpp \
  UDPPacket.cpp \
  call.cpp \
  HTTPPacket.cpp \
  IPPacket.cpp \
  IPv6Packet.cpp \
  TCPPacket.cpp \
  VRRPPacket.cpp \
    ICMPv6Packet.cpp


HEADERS += \
  ArpPacket.h \
  HTTPPacket.h \
  IPPacket.h \
  IPv6Packet.h \
  UDPPacket.h \
  DNSPacket.h \
  ICMPPacket.h \
  TCPPacket.h \
  VRRPPacket.h \
    ICMPv6Packet.h

unix {
    SOURCES += iptc.cpp
    HEADERS += iptc.h
}

win32 {
    LIBS += -lws2_32
}

win32:CONFIG(release, debug|release): LIBS += -L$$OUT_PWD/../sdk/release/ -lhungry-sniffer-sdk
else:win32:CONFIG(debug, debug|release): LIBS += -L$$OUT_PWD/../sdk/debug/ -lhungry-sniffer-sdk
else:unix: LIBS += -L$$OUT_PWD/../sdk/ -lhungry-sniffer-sdk

INCLUDEPATH += $$PWD/../sdk
DEPENDPATH += $$PWD/../sdk

OTHER_FILES += CMakeLists.txt
