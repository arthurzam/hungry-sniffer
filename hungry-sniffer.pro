CONFIG += c++11
QT     += core gui widgets

LIBS   += -lpcap++ -lpcap -ldl -lqhexedit

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = hungry-sniffer
TEMPLATE = app


SOURCES += main.cpp\
    devicechoose.cpp \
    sniff_window.cpp \
    EthernetPacket.cpp \
    packetstats.cpp

HEADERS  += \
    devicechoose.h \
    sniff_window.h \
    ThreadQueue.h \
    Protocol.h \
    EthernetPacket.h \
    packetstats.h

FORMS    += \
    devicechoose.ui \
    sniff_window.ui \
    packetstats.ui

RESOURCES += \
    icons/icons.qrc

OTHER_FILES +=