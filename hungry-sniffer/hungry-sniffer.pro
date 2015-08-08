CONFIG += c++11 link_pkgconfig
QT     += core gui
greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

LIBS   += -lpcap -ldl
QMAKE_LFLAGS_RELEASE += -flto -fno-rtti
QMAKE_CXXFLAGS_RELEASE += -flto -fno-rtti

INCLUDEPATH += $$PWD/../util

TARGET = hungry-sniffer
TEMPLATE = app

CONFIG(test) {
    DEFINES += PLUGINS_DIR=\\\"$$OUT_PWD/../plugins\\\"
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
    optionsdisabler.cpp \
    packetstable_model.cpp \
    data_structure.cpp \
    filter_tree.cpp \
    statusbar.cpp \
    preferences.cpp

HEADERS += \
    devicechoose.h \
    sniff_window.h \
    ThreadQueue.h \
    EthernetPacket.h \
    packetstats.h \
    filter_tree.h \
    optionsdisabler.h \
    additionalheaderspacket.h \
    packetstable_model.h \
    statusbar.h \
    preferences.h

FORMS += sniff_window.ui

RESOURCES += icons/icons.qrc

OTHER_FILES += hungry-sniffer.desktop

!CONFIG(no-pycmd) {
    CONFIG(python2) {
        PKGCONFIG += python2
        DEFINES += PYTHON2
    } else {
        PKGCONFIG += python3
    }
    DEFINES += PYTHON_CMD

    OTHER_FILES += hs.py
}

unix {
    isEmpty(PREFIX) {
        PREFIX = /usr
    }
    target.path = $$PREFIX/bin/

    data.path = $$PREFIX/share/hungry-sniffer/
    data.files = hs.py

    desktop.path = $$PREFIX/share/applications/
    desktop.files = hungry-sniffer.desktop

    INSTALLS += target data desktop
    QMAKE_INSTALL_FILE    = install -m 644 -p
    QMAKE_INSTALL_PROGRAM = install -m 755 -p
}

unix|win32: LIBS += -L$$OUT_PWD/../QHexEdit/ -lQHexEdit

INCLUDEPATH += $$PWD/..

include(prefs/prefs.pri)
include(widgets/widgets.pri)
