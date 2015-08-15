TEMPLATE = subdirs
SUBDIRS = hungry-sniffer hungry-sniffer-options protocols QHexEdit sdk

hungry-sniffer-options.depends = sdk
protocols.depends = sdk
hungry-sniffer.depends = QHexEdit sdk

VERSION = 1.0
unix {
    isEmpty(PREFIX) {
        PREFIX = /usr
    }
    QMAKE_INSTALL_FILE    = install -m 644 -p
    QMAKE_INSTALL_PROGRAM = install -m 755 -p
}
