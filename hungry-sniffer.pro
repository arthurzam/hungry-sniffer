CONFIG += c++11
QT     += core gui widgets printsupport
greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

LIBS   += -lpcap++ -lpcap -ldl -lqhexedit
QMAKE_LFLAGS_RELEASE += -flto
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
    optionsdisabler.cpp \
    sniff_window_python.cpp \
    history_line_edit.cpp

HEADERS  += \
    devicechoose.h \
    sniff_window.h \
    ThreadQueue.h \
    Protocol.h \
    EthernetPacket.h \
    packetstats.h \
    filter_tree.h \
    outputviewer.h \
    optionsdisabler.h \
    history_line_edit.h \
    additionalheaderspacket.h

FORMS    += \
    devicechoose.ui \
    sniff_window.ui \
    packetstats.ui \
    outputviewer.ui \
    optionsdisabler.ui

RESOURCES += \
    icons/icons.qrc

!CONFIG(no-pycmd) {
    QMAKE_CXXFLAGS += `pkg-config --cflags python3`
    LIBS += `pkg-config --libs python3`
    DEFINES += PYTHON_CMD

    OTHER_FILES += hs.py
}
