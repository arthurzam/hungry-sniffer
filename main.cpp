#include "sniff_window.h"

#include <QApplication>
#include <QLibrary>
#include <QDir>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>

#ifndef PLUGINS_DIR
#define PLUGINS_DIR "/usr/share/hungry-sniffer/plugins/"
#endif

using namespace hungry_sniffer;

inline void loadLibs()
{
    typedef void (*function_t)(HungrySniffer_Core&);

    QDir dir(PLUGINS_DIR);
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
        foo(*SniffWindow::core);
    }
}

HungrySniffer_Core* SniffWindow::core = nullptr;

inline void setMaxRam()
{
    struct rlimit limit;
    limit.rlim_cur = RLIM_INFINITY;
    limit.rlim_max = RLIM_INFINITY;
    setrlimit(RLIMIT_AS, &limit);
}

int main(int argc, char *argv[])
{
    std::vector<std::string> files;
    files.reserve(argc - 1);
    bool notEndCmdOption = true;
    for(int i = 1; i < argc; i++)
    {
        if((argv[i][0] == '-') & notEndCmdOption)
        {
            if(strcmp(argv[i], "--") == 0)
                notEndCmdOption = false;
            else if(strcmp(argv[i], "-quiet") == 0)
            {
                ::close(STDOUT_FILENO);
                ::close(STDERR_FILENO);
            }
        }
        else
        {
            files.push_back(argv[i]);
        }
    }
    setMaxRam();

    Protocol base(hungry_sniffer::init<EthernetPacket>, true, "Ethernet", true, true);
    base.addFilter("^dst *== *([^ ]+)$", EthernetPacket::filter_dstMac);
    base.addFilter("^src *== *([^ ]+)$", EthernetPacket::filter_srcMac);
    HungrySniffer_Core core(base);
    SniffWindow::core = &core;

    loadLibs();

    QApplication a(argc, argv);
    SniffWindow w;
    for(const auto& i : files)
        w.runOfflineFile(i);
    w.show();
    return a.exec();
}
