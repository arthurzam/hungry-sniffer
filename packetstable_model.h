#ifndef PACKETSTABLEMODEL_H
#define PACKETSTABLEMODEL_H

#include <QAbstractTableModel>
#include <vector>
#include <mutex>

namespace Ui {
    class SniffWindow;
}

namespace pcappp {
    class Packet;
}

namespace hungry_sniffer {
    class Packet;
    class Protocol;
}

class FilterTree;

namespace DataStructure {
    struct RawPacketData {
        uint32_t len;
        timeval time;
        char* data;

        constexpr RawPacketData() : len(0), time({0,0}), data(nullptr) {}
        RawPacketData(const pcappp::Packet& packet);
        RawPacketData(const RawPacketData& other);
        RawPacketData(RawPacketData&& other);
        RawPacketData& operator=(const RawPacketData& other);
        RawPacketData& operator=(RawPacketData&& other);
        ~RawPacketData();

        void setData(const char* data, uint32_t len);
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
        Q_OBJECT
    public:
        std::vector<DataStructure::localPacket> local;
        std::vector<int> shownPerRow;
        mutable std::mutex mutex_shownPerRow;

        static constexpr unsigned COLUMNS_COUNT = 7;
    public:
        explicit PacketsTableModel(QObject* parent = nullptr) : QAbstractTableModel(parent) {}

        int rowCount(const QModelIndex & = QModelIndex()) const
        {
            return shownPerRow.size();
        }

        int size()
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
        void clear();

        void rerunFilter(const FilterTree* filter);
        void reloadText(const hungry_sniffer::Protocol* protocol);
};

#endif // PACKETSTABLEMODEL_H
