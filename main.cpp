#include "sniff_window.h"

#include <QApplication>
#include <QLibrary>
#include <QDir>

#ifndef PLUGINS_DIRECTORY
#define PLUGINS_DIRECTORY "/home/arthur/QT/build-hungry-sniffer-Desktop-Debug/plugins/"
#endif

static void loadLibs()
{
    typedef void (*function_t)(hungry_sniffer::Protocol&);

    QDir dir(PLUGINS_DIRECTORY);
    QStringList allFiles = dir.entryList(QDir::NoDotAndDotDot | QDir::System | QDir::Hidden  | QDir::AllDirs | QDir::Files);
    allFiles.sort(Qt::CaseInsensitive);
    for(auto& iter : allFiles)
    {
        QLibrary lib(dir.absoluteFilePath(iter));
        function_t foo = (function_t)lib.resolve("add");
        if(!foo)
        {
            continue;
        }
        foo(*SniffWindow::baseProtocol);
    }
}

hungry_sniffer::Protocol* SniffWindow::baseProtocol = nullptr;

int main(int argc, char *argv[])
{
    SniffWindow::baseProtocol = new hungry_sniffer::Protocol(hungry_sniffer::init<EthernetPacket>, true, "Ethernet", true, true);
    SniffWindow::baseProtocol->addFilter("^dst *== *([^ ]+)$", EthernetPacket::filter_dstMac);
    SniffWindow::baseProtocol->addFilter("^src *== *([^ ]+)$", EthernetPacket::filter_srcMac);
    loadLibs();

    QApplication a(argc, argv);
    SniffWindow w;
    w.show();
    return a.exec();
}
