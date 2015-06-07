CONFIG += c++11
QT     += core gui
greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

LIBS   += -lpcap++ -lpcap -ldl -lqhexedit
QMAKE_LFLAGS_RELEASE += -flto -fno-rtti
QMAKE_CXXFLAGS_RELEASE += -flto -fno-rtti

TARGET = hungry-sniffer
TEMPLATE = app

CONFIG(test) {
    DEFINES += PLUGINS_DIR=\\\"$$OUT_PWD/plugins\\\"
    DEFINES += PYTHON_DIR=\\\"$$PWD/\\\"
}

SOURCES += main.cpp\
    devicechoose.cpp \
    sniff_window.cpp \
    sniff_window_packetsFlow.cpp \
    sniff_window_files.cpp \
    sniff_window_python.cpp \
    EthernetPacket.cpp \
    packetstats.cpp \
    outputviewer.cpp \
    optionsdisabler.cpp \
    history_line_edit.cpp \
    packetstable_model.cpp \
    data_structure.cpp \
    filter_tree.cpp \
    statusbar.cpp

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
    additionalheaderspacket.h \
    packetstable_model.h \
    statusbar.h

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

isEmpty(PREFIX) {
    PREFIX = /usr
}

target.path = $$PREFIX/bin/

other.path = $$PREFIX/share/hungry-sniffer/
other.files = $$OTHER_FILES

INSTALLS += target other
