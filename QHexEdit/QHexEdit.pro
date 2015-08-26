TEMPLATE = lib
TARGET      = QHexEdit
greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

*-g++* {
    QMAKE_CXXFLAGS_RELEASE += -flto -fno-rtti
}

*-msvc* {
    QMAKE_CXXFLAGS_RELEASE += /GL
}

SOURCES += \
    commands.cpp \
    qhexedit_p.cpp \
    qhexedit.cpp \
    xbytearray.cpp

HEADERS  += \
    commands.h \
    qhexedit_p.h \
    qhexedit.h \
    xbytearray.h

CONFIG += static c++11
