#include "sniff_window.h"
#include "devicechoose.h"

#include <QApplication>
#include <thread>

#include <pcap++.h>
#include <QLibrary>
#include <QDir>

void loadLibs()
{
    typedef void (*function_t)(hungry_sniffer::Protocol&);

    QDir dir("/home/arthur/QT/build-hungry-sniffer-Desktop-Debug/plugins/");
    QStringList allFiles = dir.entryList(QDir::NoDotAndDotDot | QDir::System | QDir::Hidden  | QDir::AllDirs | QDir::Files);
    QListIterator<QString> iter(allFiles);
    while(iter.hasNext())
    {
        QString name = iter.next();
        QLibrary lib(dir.absoluteFilePath(name));
        function_t foo = (function_t)lib.resolve("add");
        if(!foo)
        {
            continue;
        }
        foo(*SniffWindow::baseProtocol);
    }
}

hungry_sniffer::Protocol* SniffWindow::baseProtocol = nullptr;
#include "EthernetPacket.h"

#include <unistd.h>
#include <QMessageBox>

int main(int argc, char *argv[])
{

    SniffWindow::baseProtocol = new hungry_sniffer::Protocol(hungry_sniffer::init<EthernetPacket>, true, "Ethernet", true);
    loadLibs();

    QApplication a(argc, argv);



    SniffWindow w;
    w.show();

    return a.exec();
}
