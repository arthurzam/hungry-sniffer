CONFIG += c++11
QT     += core gui widgets printsupport

LIBS   += -lpcap++ -lpcap -ldl -lqhexedit -lqwt

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = hungry-sniffer
TEMPLATE = app


SOURCES += main.cpp\
    devicechoose.cpp \
    sniff_window.cpp \
    EthernetPacket.cpp \
    packetstats.cpp \
    filter_tree.cpp \
    filter_tree_parse.cpp \
    sniff_window_packetsFlow.cpp

HEADERS  += \
    devicechoose.h \
    sniff_window.h \
    ThreadQueue.h \
    Protocol.h \
    EthernetPacket.h \
    packetstats.h \
    filter_tree.h

FORMS    += \
    devicechoose.ui \
    sniff_window.ui \
    packetstats.ui

RESOURCES += \
    icons/icons.qrc

OTHER_FILES +=
