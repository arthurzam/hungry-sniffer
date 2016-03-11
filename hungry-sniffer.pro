TEMPLATE = subdirs
SUBDIRS = hungry-sniffer hungry-sniffer-options protocols sdk

hungry-sniffer-options.depends = sdk
protocols.depends = sdk
hungry-sniffer.depends = sdk

include(common.pri)

OTHER_FILES += CMakeLists.txt \
               VERSION
