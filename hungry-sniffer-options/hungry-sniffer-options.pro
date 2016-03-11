CONFIG   += c++11
QT       += widgets

TARGET = hungry-sniffer-options
TEMPLATE = lib

include(../common.pri)

*-g++* {
    QMAKE_CXXFLAGS_RELEASE += -flto -fno-exceptions -fno-rtti
    QMAKE_LFLAGS_RELEASE += -s -flto -fno-exceptions -fno-rtti
}

win32-g++ {
    QMAKE_LFLAGS_RELEASE += -static-libgcc -static-libstdc++ -static
    DEFINES += WIN32
}

*-msvc* {
    QMAKE_CXXFLAGS_RELEASE += /GL
    QMAKE_LFLAGS_RELEASE += /LTCG
}

SOURCES += \
    call.cpp \
    resolve_hostname.cpp \
    stats_length.cpp \
    stats_endpoints.cpp

unix: SOURCES += \
    arpspoof.cpp \
    portredirect.cpp

HEADERS +=\
    options.h \
    stats_length.h \
    stats_endpoints.h

FORMS +=

OTHER_FILES += CMakeLists.txt

win32: LIBS += -lws2_32

win32:CONFIG(release, debug|release): LIBS += -L$$OUT_PWD/../sdk/release/ -lhungry-sniffer-sdk
else:win32:CONFIG(debug, debug|release): LIBS += -L$$OUT_PWD/../sdk/debug/ -lhungry-sniffer-sdk
else:unix: LIBS += -L$$OUT_PWD/../sdk/ -lhungry-sniffer-sdk

INCLUDEPATH += $$PWD/../sdk
DEPENDPATH += $$PWD/../sdk
