#include "sniff_window.h"
#include "ui_sniff_window.h"
#include "EthernetPacket.h"
#include "packetstable_model.h"

#include <pcap.h>
#include <netinet/in.h>

#include <QFileDialog>
#include <QMessageBox>
#include <QThread>

using namespace DataStructure;

inline timeval calcDiffTimeval(const timeval& curr, const timeval& start, const timeval& base)
{
    timeval res{0, 0};
    res.tv_usec = base.tv_usec + curr.tv_usec - start.tv_usec;
    res.tv_sec = (base.tv_sec + curr.tv_sec) + ((res.tv_usec / 1000000) - start.tv_sec);
    res.tv_usec = res.tv_usec % 1000000;
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
        PACKET = 0,
        PROTOCOL
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
                uint8_t type = ObjectType::PACKET;
                ::fwrite(&type, 1, 1, file);
                ::fwrite(&packet.rawPacket.time, sizeof(packet.rawPacket.time), 1, file);
                writeBuffer(packet.rawPacket.len, packet.rawPacket.data);
                // TODO: write Own Headers
            }

            void operator <<(const hungry_sniffer::Protocol& protocol)
            {
                uint8_t type = ObjectType::PROTOCOL;
                auto names = protocol.getNameService();
                if(names.size() > 0)
                {
                    ::fwrite(&type, 1, 1, file);
                    uint16_t size = htons(names.size());
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
                len = ::fread(buffer, 1, len, file);
                return buffer;
            }

            char* readBuffer(uint32_t& len)
            {
                if(::fread(&len, 1, sizeof(len), file) != sizeof(len))
                    return NULL;
                len = ntohl(len);
                char* buffer = (char*)malloc(len);
                len = ::fread(buffer, 1, len, file);
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
                if(::fread(&packetsCount, sizeof(packetsCount), 1, file) != sizeof(packetsCount))
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
                        {
                            RawPacketData raw;
                            if(::fread(&raw.time, sizeof(raw.time), 1, file) != sizeof(raw.time))
                                return;
                            raw.data = readBuffer(raw.len);
                            if((start.tv_sec | start.tv_usec) == 0)
                                start = raw.time;
                            raw.time = calcDiffTimeval(raw.time, start, base);
                            if(packetsCount > 0)
                            {
                                SniffWindow::window->toAdd.push(std::move(raw));
                                packetsCount--;
                            }
                            break;
                        }
                        case ObjectType::PROTOCOL:
                        {
                            uint16_t size;
                            if(::fread(&size, sizeof(size), 1, file) != sizeof(size))
                                return;
                            size = ntohs(size);
                            std::string name, key, value;
                            readString(name);
                            hungry_sniffer::Protocol* protocol = const_cast<hungry_sniffer::Protocol*>(SniffWindow::core->base.findProtocol(name));
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
    QStringList filenames = QFileDialog::getOpenFileNames(this, QStringLiteral("Open File"), QStringLiteral(""),
                            QStringLiteral("All Captures (*.pcap *.hspcap);;hspcap (*.hspcap);;Pcap (*.pcap);;All files (*.*)"));
    for(auto& filename : filenames)
    {
        this->runOfflineFile(filename.toStdString());
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
            this->toAdd.push(std::move(raw));
        }
    }
    else if(ends_with(filename, ".hspcap"))
    {
        HspcapFile::Load file(filename.c_str());
        file.readAll();
        QThread::sleep(1);
        model.reloadText(&SniffWindow::core->base);
        model.rerunFilter(this->filterTree);
    }
}

void SniffWindow::on_action_save_all_triggered()
{
    if(model.local.size() == 0)
    {
        QMessageBox::warning(nullptr, QStringLiteral("Empty Table"), QStringLiteral("Packets Table is Empty"), QMessageBox::StandardButton::Ok);
        return;
    }
    QString filename = QFileDialog::getSaveFileName(this, QStringLiteral("Save File"), QStringLiteral(""),
                       QStringLiteral("hspcap (*.hspcap);;Pcap (*.pcap);;All files (*.*)"));

    if(filename.endsWith(QStringLiteral(".pcap")))
    {
        PcapFile::Save file(filename.toUtf8().constData());
        for(const auto& i : model.local)
            file << i;
    }
    else if(filename.endsWith(QStringLiteral(".hspcap")))
    {
        HspcapFile::Save file(filename.toUtf8().constData(), model.local.size());
        file << core->base;
        for(const auto& i : model.local)
            file << i;
    }
}

void SniffWindow::on_action_save_shown_triggered()
{
    if(model.local.size() == 0)
    {
        QMessageBox::warning(nullptr, QStringLiteral("Empty Table"), QStringLiteral("Packets Table is Empty"), QMessageBox::StandardButton::Ok);
        return;
    }
    QString filename = QFileDialog::getSaveFileName(this, QStringLiteral("Save File"), QStringLiteral(""),
                       QStringLiteral("hspcap (*.hspcap);;Pcap (*.pcap);;All files (*.*)"));

    if(filename.endsWith(QStringLiteral(".pcap")))
    {
        PcapFile::Save file(filename.toUtf8().constData());
        for(int& num : model.shownPerRow)
            file << model.local[num];
    }
    else if(filename.endsWith(QStringLiteral(".hspcap")))
    {
        HspcapFile::Save file(filename.toUtf8().constData(), model.shownPerRow.size());
        file << core->base;
        for(int& num : model.shownPerRow)
            file << model.local[num];
    }
}
