VERSION = 1.0
unix {
    isEmpty(PREFIX) {
        PREFIX = /usr
    }
    QMAKE_INSTALL_FILE    = install -m 644 -p
    QMAKE_INSTALL_PROGRAM = install -m 755 -p
}
