#include "packetstable_model.h"
#include "EthernetPacket.h"
#include "sniff_window.h"
#include <pcap++.h>

DataStructure::RawPacketData::RawPacketData(const pcappp::Packet& packet)
{
    this->time.tv_sec = packet.get_seconds();
    this->time.tv_usec = packet.get_miliseconds();
    setData((const char*)packet.get_data(), packet.get_length());
}

DataStructure::RawPacketData::RawPacketData(const DataStructure::RawPacketData& other) :
    time(other.time)
{
    setData(other.data, other.len);
}

DataStructure::RawPacketData::RawPacketData(DataStructure::RawPacketData&& other) :
    len(other.len),
    time(other.time),
    data(other.data)
{
    other.data = nullptr;
}

DataStructure::RawPacketData& DataStructure::RawPacketData::operator =(const RawPacketData& other)
{
    if(this != &other)
    {
        this->time = other.time;
        setData(other.data, other.len);
    }
    return *this;
}

DataStructure::RawPacketData& DataStructure::RawPacketData::operator =(RawPacketData&& other)
{
    if(this != &other)
    {
        this->len = other.len;
        this->time = other.time;
        this->data = other.data;
        other.data = nullptr;
    }
    return *this;
}

DataStructure::RawPacketData::~RawPacketData()
{
    if(this->data)
        free(this->data);
}

void DataStructure::RawPacketData::setData(const char* data, uint32_t len)
{
    this->len = len;
    this->data = (char*)malloc(len);
    memcpy(this->data, data, len);
}

DataStructure::localPacket::localPacket(DataStructure::RawPacketData&& raw) :
    rawPacket(std::move(raw)), _time(std::time(NULL)), isShown(false)
{
    this->decodedPacket = new hungry_sniffer::EthernetPacket(rawPacket.data, rawPacket.len, &SniffWindow::core->base);
}

DataStructure::localPacket& DataStructure::localPacket::operator=(DataStructure::localPacket&& other)
{
    if(this != &other)
    {
        this->rawPacket = std::move(other.rawPacket);
        this->isShown = other.isShown;
        this->_time = other._time;
        this->decodedPacket = other.decodedPacket;
        other.decodedPacket = nullptr;
    }
    return *this;
}

DataStructure::localPacket::~localPacket()
{
    if(decodedPacket)
        delete decodedPacket;
}
