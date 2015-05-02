CONFIG += c++11
QT     += core gui widgets printsupport
greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

LIBS   += -lpcap++ -lpcap -ldl -lqhexedit
QMAKE_LFLAGS_RELEASE += -s -flto
QMAKE_CXXFLAGS_RELEASE += -flto

TARGET = hungry-sniffer
TEMPLATE = app

SOURCES += main.cpp\
    devicechoose.cpp \
    sniff_window.cpp \
    EthernetPacket.cpp \
    packetstats.cpp \
    filter_tree.cpp \
    filter_tree_parse.cpp \
    sniff_window_packetsFlow.cpp \
    outputviewer.cpp \
    optionsdisabler.cpp

HEADERS  += \
    devicechoose.h \
    sniff_window.h \
    ThreadQueue.h \
    Protocol.h \
    EthernetPacket.h \
    packetstats.h \
    filter_tree.h \
    outputviewer.h \
    optionsdisabler.h

FORMS    += \
    devicechoose.ui \
    sniff_window.ui \
    packetstats.ui \
    outputviewer.ui \
    optionsdisabler.ui

RESOURCES += \
    icons/icons.qrc

TRANSLATIONS += translations/hungry-sniffer_he.ts
