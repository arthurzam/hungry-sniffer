TEMPLATE = lib
CONFIG += c++11 static
HEADERS  += \
    hs_core.h \
    hs_advanced_packets.h \
    hs_prefs.h \
    hs_protocol.h \
    hs_stats.h

unix {
    OTHER_FILES += HungrySniffer.pc

    headers.path = $$PREFIX/include/HungrySniffer
    headers.files = $$HEADERS

    pc.path = $$PREFIX/lib/pkgconfig/
    pc.files = HungrySniffer.pc

    INSTALLS += headers pc
}
