TEMPLATE = subdirs
SUBDIRS = hungry-sniffer hungry-sniffer-options protocols QHexEdit util

hungry-sniffer-options.depends = util
protocols.depends = util
hungry-sniffer.depends = QHexEdit util
