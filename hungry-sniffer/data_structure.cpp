#include "packetstable_model.h"
#include "EthernetPacket.h"
#include "sniff_window.h"

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

DataStructure::RawPacketData& DataStructure::RawPacketData::operator=(const RawPacketData& other)
{
    if(this != &other)
    {
        this->time = other.time;
        setData(other.data, other.len);
    }
    return *this;
}

DataStructure::RawPacketData& DataStructure::RawPacketData::operator=(RawPacketData&& other)
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

void DataStructure::RawPacketData::setData(const void* data, uint32_t len)
{
    this->len = len;
    this->data = (char*)malloc(len);
    memcpy(this->data, data, len);
}

DataStructure::localPacket::localPacket(DataStructure::RawPacketData&& raw) :
    rawPacket(std::move(raw)), isShown(false)
{
    this->decodedPacket = new hungry_sniffer::EthernetPacket(rawPacket.data, rawPacket.len, &SniffWindow::core->base);
}

DataStructure::localPacket& DataStructure::localPacket::operator=(DataStructure::localPacket&& other)
{
    if(this != &other)
    {
        this->rawPacket = std::move(other.rawPacket);
        this->isShown = other.isShown;
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

