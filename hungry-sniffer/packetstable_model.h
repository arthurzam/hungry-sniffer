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

#ifndef PACKETSTABLEMODEL_H
#define PACKETSTABLEMODEL_H

#include <QAbstractTableModel>
#include <vector>
#include <mutex>

namespace hungry_sniffer {
    class Packet;
    class Protocol;
}

class FilterTree;

namespace DataStructure {
    struct RawPacketData {
        uint32_t len;
        struct timeval time;
        char* data;

        constexpr RawPacketData() : len(0), time({0,0}), data(nullptr) {}
        RawPacketData(const RawPacketData& other);
        RawPacketData(RawPacketData&& other);
        RawPacketData& operator=(const RawPacketData& other);
        RawPacketData& operator=(RawPacketData&& other);
        ~RawPacketData();

        void setData(const void* data, uint32_t len);
    };

    struct localPacket {
        RawPacketData rawPacket;
        hungry_sniffer::Packet* decodedPacket = nullptr;
        bool isShown;

        localPacket(localPacket&& other) : rawPacket(std::move(other.rawPacket)),
            decodedPacket(other.decodedPacket), isShown(other.isShown)
        {
            other.decodedPacket = nullptr;
        }

        localPacket(const localPacket& other) = delete;
        localPacket(RawPacketData&& raw);
        localPacket& operator=(const localPacket& other) = delete;
        localPacket& operator=(localPacket&& other);

        ~localPacket();
    };
}

class PacketsTableModel : public QAbstractTableModel
{
    public:
        std::vector<DataStructure::localPacket> local;
        std::vector<int> shownPerRow;
        mutable std::mutex mutex_shownPerRow;
        bool showColors = true;

        static constexpr unsigned COLUMNS_COUNT = 7;
    public:
        explicit PacketsTableModel(QObject* parent = nullptr) : QAbstractTableModel(parent) {}

        int rowCount(const QModelIndex & = QModelIndex()) const
        {
            return shownPerRow.size();
        }

        int columnCount(const QModelIndex & = QModelIndex()) const
        {
            return COLUMNS_COUNT;
        }

        QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const;
        QVariant headerData(int section, Qt::Orientation orientation, int role) const;

        void append(DataStructure::localPacket&& obj);
        void remove(int row);
        void removeAll();
        void removeShown();

        void rerunFilter(const FilterTree* filter);
        void reloadText(const hungry_sniffer::Protocol* protocol);
};

#endif // PACKETSTABLEMODEL_H
