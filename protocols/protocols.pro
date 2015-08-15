TEMPLATE = lib
greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++11 link_pkgconfig
unix: PKGCONFIG += jsoncpp

TARGET = hungry-sniffer-protocols
TEMPLATE = lib

QMAKE_LFLAGS_RELEASE += -s -flto -Bsymbolic-functions -fno-exceptions -fno-rtti
QMAKE_CXXFLAGS_RELEASE += -flto -Bsymbolic-functions -fno-exceptions -fno-rtti

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
  VRRPPacket.cpp


HEADERS += \
  ArpPacket.h \
  HTTPPacket.h \
  IPPacket.h \
  IPv6Packet.h \
  UDPPacket.h \
  DNSPacket.h \
  ICMPPacket.h \
  TCPPacket.h \
  VRRPPacket.h

INCLUDEPATH += $$PWD/../sdk

unix {
    SOURCES += iptc.cpp \
      PacketJson.cpp
    HEADERS += iptc.h \
      PacketJson.h
}

win32 {
    LIBS += -lws2_32
}
