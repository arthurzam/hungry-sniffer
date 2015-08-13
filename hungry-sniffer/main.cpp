/*
    Copyright (c) 2015 Zamarin Arthur

    Permission is hereby granted, free of charge, to any person obtaining
    a copy of this software and associated documentation files (the "Software"),
    to deal in the Software without restriction, including without limitation
    the rights to use, copy, modify, merge, publish, distribute, sublicense,
    and/or sell copies of the Software, and to permit persons to whom the Software
    is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
    EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
    OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
    IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
    CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
    TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
    OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include <QApplication>
#include <QDir>
#include <QLibrary>
#include <QSettings>

#if defined(Q_OS_WIN)

#elif defined(Q_OS_UNIX)
    #include <sys/time.h>
    #include <sys/resource.h>
    #include <unistd.h>
#endif

#include "EthernetPacket.h"
#include "preferences.h"
#include "sniff_window.h"

#include <hs_core.h>

#ifndef PLUGINS_DIR
#define PLUGINS_DIR "/usr/share/hungry-sniffer/plugins/"
#endif

void addPrefs(HungrySniffer_Core& core);

using namespace hungry_sniffer;

inline void loadLibs(const QString& path)
{
    typedef void (*function_t)(HungrySniffer_Core&);

    QDir dir(path);
    QStringList allFiles = dir.entryList(QDir::NoDotAndDotDot | QDir::System | QDir::Hidden  | QDir::AllDirs | QDir::Files);
    allFiles.sort(Qt::CaseInsensitive);
    for(const auto& iter : allFiles)
    {
        QLibrary lib(dir.absoluteFilePath(iter));
        function_t foo = (function_t)lib.resolve("add");
        if(foo)
        {
            try {
                foo(*SniffWindow::core);
#ifndef QT_NO_DEBUG
            } catch (const std::exception& e) {
                qDebug("error with %s: %s", iter.toLatin1().constData(), e.what());
#endif
                continue;
            } catch (...) {
#ifndef QT_NO_DEBUG
                qDebug("error with %s:", iter.toLatin1().constData());
#endif
                continue;
            }
            Preferences::reloadFunc_t reload = (Preferences::reloadFunc_t)lib.resolve("reload");
            if(reload)
                Preferences::reloadFunctions.push_back(reload);
        }
    }
}

HungrySniffer_Core* SniffWindow::core = nullptr;
QSettings* Preferences::settings = nullptr;

int main(int argc, char *argv[])
{
    Protocol base(init<EthernetPacket>, "Ethernet", Protocol::getFlags(true, true));
    base.addFilter("^dst *== *([^ ]+)$", EthernetPacket::filter_dstMac);
    base.addFilter("^src *== *([^ ]+)$", EthernetPacket::filter_srcMac);
    HungrySniffer_Core core(base);
    SniffWindow::core = &core;

#ifdef QT_NO_DEBUG
    QSettings settings(QSettings::IniFormat, QSettings::UserScope, QStringLiteral("hungrysniffer"));
#else
    QSettings settings(QStringLiteral("settings.conf"), QSettings::IniFormat);
#endif
    Preferences::settings = &settings;

    addPrefs(*SniffWindow::core);

    { // plugins load
        loadLibs(QStringLiteral(PLUGINS_DIR));
        settings.beginGroup(QStringLiteral("General"));
        settings.beginGroup(QStringLiteral("Modules"));
        QVariant var = settings.value(QStringLiteral("plugins_dir"));
        if(!var.isNull())
        {
            for(const QString& path : var.toStringList())
                loadLibs(path);
        }
        settings.endGroup();
        settings.endGroup();
    }

    QApplication a(argc, argv);
    a.setApplicationVersion(APP_VERSION);
    SniffWindow w;

    bool notEndCmdOption = true;
    for(int i = 1; i < argc; i++)
    {
        if((argv[i][0] == '-') & notEndCmdOption)
        {
            if(strcmp(argv[i] + 1, "-") == 0)
                notEndCmdOption = false;
            else if(i + 1 < argc && strcmp(argv[i] + 1, "i") == 0)
                w.runLivePcap(argv[++i], 0, QString());
#if defined(Q_OS_UNIX)
            else if(strcmp(argv[i] + 1, "quiet") == 0)
            {
                ::close(STDOUT_FILENO);
                ::close(STDERR_FILENO);
            }
#endif
        }
        else
        {
            w.runOfflineFile(argv[i]);
        }
    }

    w.show();
    return a.exec();
}
