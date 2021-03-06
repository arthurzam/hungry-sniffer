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
    #include <unistd.h>
#endif

#include "about_plugins.h"
#include "EthernetPacket.h"
#include "preferences.h"
#include "sniff_window.h"

#include <hs_plugin.h>

static QString getPluginsPath()
{
#ifdef PLUGINS_DIR
    return QStringLiteral(PLUGINS_DIR);
#elif defined(Q_OS_WIN)
    return QApplication::applicationDirPath().append("/plugins");
#elif defined(Q_OS_UNIX)
    return QStringLiteral("/usr/share/hungry-sniffer/plugins");
#else
    return QStringLiteral("./plugins");
#endif
}

void addPrefs(HungrySniffer_Core& core);

using namespace hungry_sniffer;

inline void loadLibs(const QString& path)
{
    typedef void (*add_function_t)();
    typedef uint32_t (*info_uint32_t)();

    QDir dir(path);
    QStringList allFiles = dir.entryList(QDir::NoDotAndDotDot | QDir::System | QDir::Hidden  | QDir::AllDirs | QDir::Files);
    allFiles.sort(Qt::CaseInsensitive);
    for(const auto& iter : allFiles)
    {
        QLibrary lib(dir.absoluteFilePath(iter));
        info_uint32_t info_version = (info_uint32_t)lib.resolve("PLUGIN_VERSION");
        if(info_version && info_version() != API_VERSION)
        {
#ifndef QT_NO_DEBUG
            qDebug("plugin %s version isn't matching", iter.toLatin1().constData());
#endif
            continue;
        }
        add_function_t add = (add_function_t)lib.resolve("add");
        if(add)
        {
            try {
                add();
#ifndef QT_NO_DEBUG
            } catch (const std::exception& e) {
                qDebug("error with %s: %s", iter.toLatin1().constData(), e.what());
                continue;
#endif
            } catch (...) {
#ifndef QT_NO_DEBUG
                qDebug("error with %s", iter.toLatin1().constData());
#endif
                continue;
            }
        }
        Preferences::reloadFunc_t reload = (Preferences::reloadFunc_t)lib.resolve("reload");
        if(reload)
            Preferences::reloadFunctions.push_back(reload);
        AboutPlugins::window->addPlugin(lib);
    }
}

QSettings* Preferences::settings = nullptr;

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    a.setApplicationVersion(APP_VERSION);
    AboutPlugins::init();

    Protocol base(init<EthernetPacket>, "Ethernet", Protocol::getFlags(true, true));
    base.addFilter("^dst *== *([^ ]+)$", EthernetPacket::filter_dstMac);
    base.addFilter("^src *== *([^ ]+)$", EthernetPacket::filter_srcMac);
    base.addFilter("^follow *== *([^ ]+) *, *([^ ]+)$", EthernetPacket::filter_follow);
    HungrySniffer_Core core(base);
    HungrySniffer_Core::core = &core;

    QSettings settings(QSettings::IniFormat, QSettings::UserScope, QStringLiteral("hungrysniffer"));
    Preferences::settings = &settings;

    { // plugins load
        loadLibs(getPluginsPath());
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
    addPrefs(*HungrySniffer_Core::core);
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
