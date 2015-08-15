TEMPLATE = subdirs
SUBDIRS = hungry-sniffer hungry-sniffer-options protocols QHexEdit sdk

hungry-sniffer-options.depends = sdk
protocols.depends = sdk
hungry-sniffer.depends = QHexEdit sdk
