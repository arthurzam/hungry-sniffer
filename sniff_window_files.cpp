#include "sniff_window.h"
#include "ui_sniff_window.h"
#include "EthernetPacket.h"
#include "packetstable_model.h"

#include <pcap.h>
#include <pcap++.h>
#include <netinet/in.h>

using namespace DataStructure;

enum ObjectType {
    PACKET = 0,
    PROTOCOL
};

static bool savePcap(const char* filename, const std::vector<localPacket>& packets)
{
    pcap_t* pd = pcap_open_dead(DLT_EN10MB, 65535);
    pcap_dumper_t* pdumper = pcap_dump_open(pd, filename);
    for(const auto& i : packets)
    {
        struct pcap_pkthdr pkhdr;
        pkhdr.caplen = pkhdr.len = i.rawPacket.len;
        pkhdr.ts = i.rawPacket.time;
        pcap_dump((u_char*)pdumper, &pkhdr, (const u_char*)i.rawPacket.data);
    }
    pcap_dump_close(pdumper);
    pcap_close(pd);
    return true;
}

inline char* readBuffer(FILE* file, uint16_t& len)
{
    ::fread(&len, 1, sizeof(len), file);
    len = ntohs(len);
    char* buffer = (char*)malloc(len);
    len = ::fread(buffer, 1, len, file);
    return buffer;
}

inline char* readBuffer(FILE* file, uint32_t& len)
{
    ::fread(&len, 1, sizeof(len), file);
    len = ntohl(len);
    char* buffer = (char*)malloc(len);
    len = ::fread(buffer, 1, len, file);
    return buffer;
}

inline std::string& readString(FILE* file, std::string& str)
{
    uint16_t len;
    char* buffer = readBuffer(file, len);
    str = std::string(buffer, len);
    free(buffer);
    return str;
}

inline void writeBuffer(FILE* file, uint16_t len, const void* buffer)
{
    uint16_t temp = ntohs(len);
    ::fwrite(&temp, 1, sizeof(temp), file);
    ::fwrite(buffer, 1, len, file);
}

inline void writeBuffer(FILE* file, uint32_t len, const void* buffer)
{
    uint32_t temp = ntohl(len);
    ::fwrite(&temp, 1, sizeof(temp), file);
    ::fwrite(buffer, 1, len, file);
}

inline void writeString(FILE* file, const std::string& str)
{
    writeBuffer(file, (uint16_t)str.length(), str.c_str());
}

static void saveHspcapProtocol(FILE* file, const hungry_sniffer::Protocol& protocol)
{
    uint8_t type = ObjectType::PROTOCOL;
    auto names = protocol.getNameService();
    if(names.size() > 0)
    {
        ::fwrite(&type, 1, 1, file);
        uint16_t size = htons(names.size());
        ::fwrite(&size, sizeof(size), 1, file);
        writeString(file, protocol.getName());
        for(auto& i : names)
        {
            writeString(file, i.first);
            writeString(file, i.second);
        }
    }

    for(auto& i : protocol.getProtocolsDB())
    {
        saveHspcapProtocol(file, i.second);
    }
}

static bool saveHspcap(const char* filename, const std::vector<localPacket>& packets)
{
    FILE* file = fopen(filename, "wb");
    uint32_t packetsCount = htonl(packets.size());
    ::fwrite(&packetsCount, sizeof(packetsCount), 1, file);
    saveHspcapProtocol(file, SniffWindow::core->base);
    uint8_t type = ObjectType::PACKET;
    for(const auto& i : packets)
    {
        ::fwrite(&type, 1, 1, file);
        ::fwrite(&i.rawPacket.time, sizeof(i.rawPacket.time), 1, file);
        writeBuffer(file, i.rawPacket.len, i.rawPacket.data);
    }

    fclose(file);
    return true;
}

inline timeval calcDiffTimeval(const timeval& curr, const timeval& start, const timeval& base)
{
    timeval res{0,0};
    res.tv_usec = base.tv_usec + curr.tv_usec - start.tv_usec;
    res.tv_sec = (base.tv_sec + curr.tv_sec) + ((res.tv_usec / 1000000) - start.tv_sec);
    res.tv_usec = res.tv_usec % 1000000;
    return res;
}

static bool readHspcap(const char* filename)
{
    FILE* file = fopen(filename, "rb");
    uint32_t packetsCount = 0;
    ::fread(&packetsCount, sizeof(packetsCount), 1, file);
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
                ::fread(&raw.time, sizeof(raw.time), 1, file);
                raw.data = readBuffer(file, raw.len);
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
                ::fread(&size, sizeof(size), 1, file);
                size = ntohs(size);
                std::string name, key, value;
                readString(file, name);
                hungry_sniffer::Protocol* protocol = const_cast<hungry_sniffer::Protocol*>(SniffWindow::core->base.findProtocol(name));
                if(protocol)
                {
                    for(int i = size; i != 0; --i)
                    {
                        readString(file, key);
                        readString(file, value);
                        protocol->associateName(key, value);
                    }
                }
                break;
            }
        }
    }
    fclose(file);
    return true;
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

void SniffWindow::runOfflineOpen_p(const std::string &filename)
{
    if(ends_with(filename, ".pcap"))
    {
        pcappp::PcapOffline off(filename);
        pcappp::Packet p;
        timeval start{0, 0};
        timeval base{0, 0};
        gettimeofday(&base, 0);
        while(this->toNotStop && off.next(p))
        {
            RawPacketData raw(p);
            if((start.tv_sec | start.tv_usec) == 0)
                start = raw.time;
            raw.time = calcDiffTimeval(raw.time, start, base);
            this->toAdd.push(std::move(raw));
        }
    }
    else if(ends_with(filename, ".hspcap"))
    {
        readHspcap(filename.c_str());
        QThread::sleep(1);
        model.reloadText(&SniffWindow::core->base);
        model.rerunFilter(this->filterTree);
    }
}

void SniffWindow::on_actionSave_triggered()
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
        savePcap(filename.toUtf8().constData(), model.local);
    }
    else if(filename.endsWith(QStringLiteral(".hspcap")))
    {
        saveHspcap(filename.toUtf8().constData(), model.local);
    }
}
