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

#ifndef Q_COMPILER_INITIALIZER_LISTS
#define Q_COMPILER_INITIALIZER_LISTS
#endif

#include "sniff_window.h"
#include "ui_sniff_window.h"
#include "EthernetPacket.h"
#include "packetstable_model.h"

#include <hs_core.h>

#if defined(Q_OS_WIN)
    #include <winsock2.h>
    #include <windows.h>
#elif defined(Q_OS_UNIX)
#endif
#include <pcap.h>
#include <QFileDialog>
#include <QMessageBox>
#include <QThread>
#if defined(Q_OS_WIN)
    #if defined(_MSC_VER) || defined(_MSC_EXTENSIONS)
        #define DELTA_EPOCH_IN_MICROSECS  11644473600000000Ui64
    #else
        #define DELTA_EPOCH_IN_MICROSECS  11644473600000000ULL
    #endif
    int gettimeofday(struct timeval *tv, struct timezone*)
    {
        FILETIME ft;
        unsigned __int64 tmpres = 0;
        if (NULL != tv)
        {
            GetSystemTimeAsFileTime(&ft);

            tmpres |= ft.dwHighDateTime;
            tmpres <<= 32;
            tmpres |= ft.dwLowDateTime;

            tmpres /= 10;  /*convert into microseconds*/
            /*converting file time to unix epoch*/
            tmpres -= DELTA_EPOCH_IN_MICROSECS;
            tv->tv_sec = (long)(tmpres / 1000000UL);
            tv->tv_usec = (long)(tmpres % 1000000UL);
        }
        return 0;
    }
#elif defined(Q_OS_UNIX)
    #include <netinet/in.h>
#endif

using namespace DataStructure;

inline timeval calcDiffTimeval(const timeval& curr, const timeval& start, const timeval& base)
{
    timeval res;
    res.tv_usec = base.tv_usec + curr.tv_usec - start.tv_usec;
    res.tv_sec = base.tv_sec + curr.tv_sec - start.tv_sec;
    if(res.tv_usec < 0)
    {
        res.tv_usec += 1000000;
        --res.tv_sec;
    }
    else if(res.tv_usec > 1000000)
    {
        res.tv_usec -= 1000000;
        ++res.tv_sec;
    }
    return res;
}

namespace PcapFile {
    class Save
    {
        private:
            pcap_t* pd;
            pcap_dumper_t* pdumper;
        public:
            Save(const char* filename)
            {
                pd = pcap_open_dead(DLT_EN10MB, 65535);
                pdumper = pcap_dump_open(pd, filename);
            }

            void operator <<(const localPacket& packet)
            {
                struct pcap_pkthdr pkhdr;
                pkhdr.caplen = pkhdr.len = packet.rawPacket.len;
                pkhdr.ts = packet.rawPacket.time;
                pcap_dump((u_char*)pdumper, &pkhdr, (const u_char*)packet.rawPacket.data);
            }

            ~Save()
            {
                pcap_dump_close(pdumper);
                pcap_close(pd);
            }
    };

    class Load
    {
        private:
            pcap_t* pd;

        public:
            Load(const char* filename)
            {
                pd = pcap_open_offline(filename, NULL);
            }

            bool operator >>(RawPacketData& raw)
            {
                struct pcap_pkthdr* header;
                const u_char* data;

                int returnValue = pcap_next_ex(pd, &header, &data);
                if(returnValue != 1)
                    return false;
                if(header->caplen != header->len)
                    return false;
                raw.setData(data, header->len);
                raw.time = header->ts;
                return true;
            }

            ~Load()
            {
                pcap_close(pd);
            }
    };
}

namespace HspcapFile {

    enum ObjectType
    {
        PROTOCOL = 0,
        PACKET,
        PACKET_HEADERS
    };

    class Save
    {
        private:
            FILE* file;

            void writeBuffer(uint16_t len, const void* buffer)
            {
                uint16_t temp = ntohs(len);
                ::fwrite(&temp, 1, sizeof(temp), file);
                ::fwrite(buffer, 1, len, file);
            }

            void writeBuffer(uint32_t len, const void* buffer)
            {
                uint32_t temp = ntohl(len);
                ::fwrite(&temp, 1, sizeof(temp), file);
                ::fwrite(buffer, 1, len, file);
            }

            void writeString(const std::string& str)
            {
                writeBuffer((uint16_t)str.length(), str.c_str());
            }

        public:
            Save(const char* filename, uint32_t packetsCount)
            {
                file = fopen(filename, "wb");
                packetsCount = htonl(packetsCount);
                ::fwrite(&packetsCount, sizeof(packetsCount), 1, file);
            }

            void operator <<(const localPacket& packet)
            {
                auto headers = packet.rawPacket.additionalHeaders;
                uint8_t type = (headers ? ObjectType::PACKET_HEADERS : ObjectType::PACKET);
                ::fwrite(&type, 1, 1, file);
                ::fwrite(&packet.rawPacket.time, sizeof(packet.rawPacket.time), 1, file);
                writeBuffer(packet.rawPacket.len, packet.rawPacket.data);
                if(headers && headers->size() != 0)
                {
                    uint16_t count = htons((uint16_t)headers->size());
                    ::fwrite(&count, sizeof(count), 1, file);
                    for(auto& i : *headers)
                    {
                        writeString(i.first.toStdString());
                        writeString(i.second.toStdString());
                    }
                }
            }

            void operator <<(const hungry_sniffer::Protocol& protocol)
            {
                uint8_t type = ObjectType::PROTOCOL;
                auto names = protocol.getNameService();
                if(names.size() > 0)
                {
                    ::fwrite(&type, 1, 1, file);
                    uint16_t size = htons((uint16_t)names.size());
                    ::fwrite(&size, sizeof(size), 1, file);
                    writeString(protocol.getName());
                    for(auto& i : names)
                    {
                        writeString(i.first);
                        writeString(i.second);
                    }
                }

                for(auto& i : protocol.getProtocolsDB())
                {
                    *this << i.second;
                }
            }

            ~Save()
            {
                fclose(file);
                file = NULL;
            }
    };

    class Load
    {
        private:
            FILE* file;

            char* readBuffer(uint16_t& len)
            {
                if(::fread(&len, 1, sizeof(len), file) != sizeof(len))
                    return NULL;
                len = ntohs(len);
                char* buffer = (char*)malloc(len);
                len = (uint16_t)::fread(buffer, 1, len, file);
                return buffer;
            }

            char* readBuffer(uint32_t& len)
            {
                if(::fread(&len, 1, sizeof(len), file) != sizeof(len))
                    return NULL;
                len = ntohl(len);
                char* buffer = (char*)malloc(len);
                len = (uint16_t)::fread(buffer, 1, len, file);
                return buffer;
            }

            std::string& readString(std::string& str)
            {
                uint16_t len;
                char* buffer = readBuffer(len);
                str = std::string(buffer, len);
                free(buffer);
                return str;
            }

        public:
            Load(const char* filename)
            {
                file = fopen(filename, "rb");
            }

            void readAll()
            {
                uint32_t packetsCount = 0;
                if(::fread(&packetsCount, sizeof(packetsCount), 1, file) != 1)
                    return;
                packetsCount = ntohl(packetsCount);
                uint8_t type;

                timeval start{0, 0};
                timeval base{0, 0};
                gettimeofday(&base, 0);

                while(::fread(&type, 1, 1, file) == 1)
                {
                    switch(type)
                    {
                        case ObjectType::PACKET:
                        case ObjectType::PACKET_HEADERS:
                        {
                            RawPacketData raw;
                            if(::fread(&raw.time, sizeof(raw.time), 1, file) != 1)
                                return;
                            raw.data = readBuffer(raw.len);
                            if((start.tv_sec | start.tv_usec) == 0)
                                start = raw.time;
                            raw.time = calcDiffTimeval(raw.time, start, base);
                            if(type == ObjectType::PACKET_HEADERS)
                            {
                                uint16_t count;
                                ::fread(&count, sizeof(count), 1, file);
                                auto headers = raw.additionalHeaders = new std::vector<std::pair<QString, QString>>();
                                std::string key, value;
                                for(int i = ntohs(count); i != 0; i--)
                                {
                                    readString(key);
                                    readString(value);
                                    headers->push_back({QString::fromStdString(key), QString::fromStdString(value)});
                                }
                            }
                            if(packetsCount > 0)
                            {
                                emit SniffWindow::window->pushPacket(new RawPacketData(std::move(raw)));
                                packetsCount--;
                            }
                            break;
                        }
                        case ObjectType::PROTOCOL:
                        {
                            uint16_t size;
                            if(::fread(&size, sizeof(size), 1, file) != 1)
                                return;
                            size = ntohs(size);
                            std::string name, key, value;
                            readString(name);
                            hungry_sniffer::Protocol* protocol = const_cast<hungry_sniffer::Protocol*>(HungrySniffer_Core::core->base.findProtocol(name));
                            if(protocol)
                            {
                                for(int i = size; i != 0; --i)
                                {
                                    readString(key);
                                    readString(value);
                                    protocol->associateName(key, value);
                                }
                            }
                            break;
                        }
                    }
                }
            }

            ~Load()
            {
                fclose(file);
                file = NULL;
            }
    };
}

void SniffWindow::on_actionOpen_triggered()
{
    QStringList filenames = QFileDialog::getOpenFileNames(this, QStringLiteral("Open File"), default_open_location,
                            QStringLiteral("All Captures (*.pcap *.hspcap);;hspcap (*.hspcap);;Pcap (*.pcap);;All files (*.*)"));
    for(auto& filename : filenames)
    {
        this->runOfflineFile(filename.toStdString());
        this->recentFiles_paths.removeAll(filename);
        this->recentFiles_paths.prepend(filename);
        updateRecentsMenu();
    }
}

inline bool ends_with(const std::string& value, const std::string& ending)
{
    if (ending.size() > value.size()) return false;
    return std::equal(ending.rbegin(), ending.rend(), value.rbegin());
}

void SniffWindow::runOfflineOpen_p(const std::string& filename)
{
    if(ends_with(filename, ".pcap"))
    {
        PcapFile::Load reader(filename.c_str());
        RawPacketData raw;
        timeval start{0, 0};
        timeval base{0, 0};
        gettimeofday(&base, 0);
        while(this->toNotStop && reader >> raw)
        {
            if((start.tv_sec | start.tv_usec) == 0)
                start = raw.time;
            raw.time = calcDiffTimeval(raw.time, start, base);
            emit this->pushPacket(new RawPacketData(std::move(raw)));
        }
    }
    else if(ends_with(filename, ".hspcap"))
    {
        HspcapFile::Load file(filename.c_str());
        file.readAll();
        QThread::sleep(1);
        model.reloadText(&HungrySniffer_Core::core->base);
        model.rerunFilter(this->filterTree);
    }
}

QString saveFileDialog(QString& filter)
{
    QFileDialog open;
    open.setFileMode(QFileDialog::AnyFile);
    open.setViewMode(QFileDialog::Detail);
    open.setNameFilters(QStringList({QStringLiteral("hspcap (*.hspcap)"), QStringLiteral("Pcap (*.pcap)"), QStringLiteral("All files (*.*)")}));
    if(!open.exec())
        return QStringLiteral("");
    filter = open.selectedNameFilter();
    return open.selectedFiles().first();
}

void SniffWindow::on_action_save_all_triggered()
{
    if(model.local.size() == 0)
    {
        QMessageBox::warning(nullptr, QStringLiteral("Empty Table"), QStringLiteral("Packets Table is Empty"), QMessageBox::StandardButton::Ok);
        return;
    }
    QString fil;
    QString filename = saveFileDialog(fil);
    if(fil == QStringLiteral("Pcap (*.pcap)"))
    {
        PcapFile::Save file(filename.toUtf8().constData());
        for(const auto& i : model.local)
            file << i;
    }
    else if(fil == QStringLiteral("hspcap (*.hspcap)"))
    {
        HspcapFile::Save file(filename.toUtf8().constData(), (uint32_t)model.local.size());
        file << HungrySniffer_Core::core->base;
        for(const auto& i : model.local)
            file << i;
    }
}

void SniffWindow::on_action_save_shown_triggered()
{
    if(model.shownPerRow.size() == 0)
    {
        QMessageBox::warning(nullptr, QStringLiteral("Empty Table"), QStringLiteral("Packets Table is Empty"), QMessageBox::StandardButton::Ok);
        return;
    }
    QString fil;
    QString filename = saveFileDialog(fil);
    if(fil == QStringLiteral("Pcap (*.pcap)"))
    {
        PcapFile::Save file(filename.toUtf8().constData());
        for(int& num : model.shownPerRow)
            file << model.local[num];
    }
    else if(fil == QStringLiteral("hspcap (*.hspcap)"))
    {
        HspcapFile::Save file(filename.toUtf8().constData(), (uint32_t)model.shownPerRow.size());
        file << HungrySniffer_Core::core->base;
        for(int& num : model.shownPerRow)
            file << model.local[num];
    }
}
