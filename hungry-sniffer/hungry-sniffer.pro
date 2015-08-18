CONFIG += c++11 link_pkgconfig
QT     += core gui
greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = hungry-sniffer
TEMPLATE = app

include(../common.pri)

win32: LIBS += -lwpcap -lws2_32
unix: LIBS += -lpcap -ldl
win32: DEFINES += WIN32

QMAKE_LFLAGS_RELEASE += -flto -fno-rtti
QMAKE_CXXFLAGS_RELEASE += -flto -fno-rtti

INCLUDEPATH += $$PWD/../sdk

DEFINES += APP_VERSION=\\\"$$VERSION\\\"

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
    preferences.cpp \
    about.cpp

HEADERS += \
    devicechoose.h \
    sniff_window.h \
    ThreadQueue.h \
    EthernetPacket.h \
    packetstats.h \
    filter_tree.h \
    optionsdisabler.h \
    packetstable_model.h \
    statusbar.h \
    preferences.h \
    about.h

FORMS += sniff_window.ui

RESOURCES += icons/icons.qrc

unix: OTHER_FILES += hungry-sniffer.desktop

!CONFIG(no-pycmd) {
    unix {
        CONFIG(python2) {
            PKGCONFIG += python2
        } else {
            PKGCONFIG += python3
        }
    }

    win32 {
        isEmpty(PYTHON_VERSION) {
            PYTHON_VERSION=34
        }
        isEmpty(PYTHON_PATH) {
            PYTHON_PATH = C:/Python$$PYTHON_VERSION
        }
        LIBS += -L$$PYTHON_PATH/libs -lpython$$PYTHON_VERSION
        INCLUDEPATH += $$PYTHON_PATH/include
    }
    DEFINES += PYTHON_CMD

    OTHER_FILES += hs.py
}

unix {
    target.path = $$PREFIX/bin/

    data.path = $$PREFIX/share/hungry-sniffer/
    data.files = hs.py

    desktop.path = $$PREFIX/share/applications/
    desktop.files = hungry-sniffer.desktop

    INSTALLS += target data desktop
}

unix|win32: LIBS += -L$$OUT_PWD/../QHexEdit/ -lQHexEdit

INCLUDEPATH += $$PWD/..

include(prefs/prefs.pri)
include(widgets/widgets.pri)
