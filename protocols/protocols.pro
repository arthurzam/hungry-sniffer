TEMPLATE = lib
CONFIG -= app_bundle qt

CONFIG += c++11

TARGET = hungry-sniffer-protocols
TEMPLATE = lib

QMAKE_LFLAGS_RELEASE += -s -flto -Bsymbolic-functions -fno-exceptions -fno-rtti
QMAKE_CXXFLAGS_RELEASE += -flto -Bsymbolic-functions -fno-exceptions -fno-rtti

SOURCES += \
  ArpPacket.cpp \
  DNSPacket.cpp \
  ICMPPacket.cpp \
  iptc.cpp \
  PacketJson.cpp \
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
  Protocol.h \
  UDPPacket.h \
  DNSPacket.h \
  ICMPPacket.h \
  iptc.h \
  PacketJson.h \
  TCPPacket.h \
  VRRPPacket.h
