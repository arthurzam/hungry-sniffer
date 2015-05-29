#include "packetstable_model.h"
#include "Protocol.h"
#include "filter_tree.h"

#include <QBrush>

QVariant PacketsTableModel::data(const QModelIndex &index, int role) const
{
    if(index.row() >= (int)shownPerRow.size())
        return QVariant();
    int number = shownPerRow[index.row()];
    const DataStructure::localPacket& packet = local[number];

    switch(role)
    {
        case Qt::ItemDataRole::ToolTipRole:
        case Qt::ItemDataRole::DisplayRole:
            switch(index.column())
            {
                case 0:
                    return QVariant(number + 1);
                case 1:
                    return QVariant(0); // TODO: put time diff
                case 2:
                    return QString::fromStdString(packet.decodedPacket->getName());
                case 3:
                    return QString::fromStdString(packet.decodedPacket->getSource());
                case 4:
                    return QString::fromStdString(packet.decodedPacket->getDestination());
                case 5:
                    return (packet.decodedPacket->isGoodPacket() ? QString::fromStdString(packet.decodedPacket->getInfo()) : QStringLiteral("Bad Packet"));
            }
            break;
        case Qt::ItemDataRole::BackgroundRole:
            if(!packet.decodedPacket->isGoodPacket())
            {
                return QBrush(Qt::yellow);
            }
            break;
    }
    return QVariant();
}

QVariant PacketsTableModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    static const QString headers[] = {QStringLiteral("No."), QStringLiteral("Arrival Time"), QStringLiteral("Protocol"),
                                      QStringLiteral("Source"), QStringLiteral("Destination"), QStringLiteral("Info")};
    static_assert(sizeof(headers) == COLUMNS_COUNT * sizeof(QString), "bad COLUMNS_COUNT");
    if ((role == Qt::DisplayRole) & (orientation == Qt::Horizontal)) {
        return headers[section];
    }

    return QVariant();
}

void PacketsTableModel::append(DataStructure::localPacket&& obj)
{
    this->local.push_back(std::move(obj));
    if(this->local.back().isShown)
    {
        mutex_shownPerRow.lock();
        int row = this->shownPerRow.size();
        beginInsertRows(QModelIndex(), row, row);
        this->shownPerRow.push_back(this->local.size() - 1);
        mutex_shownPerRow.unlock();
        endInsertRows();
    }
}

void PacketsTableModel::remove(int row)
{
    if(row >= (int)shownPerRow.size()) return;
    beginRemoveRows(QModelIndex(), row, row);
    mutex_shownPerRow.lock();
    int loc = shownPerRow[row];
    shownPerRow.erase(shownPerRow.begin() + row);
    local.erase(local.begin() + loc);
    mutex_shownPerRow.unlock();
    endRemoveRows();
}

void PacketsTableModel::clear()
{
    beginResetModel();
    mutex_shownPerRow.lock();
    this->shownPerRow.clear();
    mutex_shownPerRow.unlock();
    this->local.clear();
    endResetModel();
}

void PacketsTableModel::rerunFilter(const FilterTree* filter)
{
    beginResetModel();
    mutex_shownPerRow.lock();
    this->shownPerRow.clear();
    int i = 0;
    for(auto& p : this->local)
    {
        if((p.isShown = !(bool)filter || filter->get(p.decodedPacket)))
        {
            this->shownPerRow.push_back(i);
        }
        ++i;
    }
    mutex_shownPerRow.unlock();
    endResetModel();
}

void PacketsTableModel::reloadText(const hungry_sniffer::Protocol* protocol)
{
    this->beginResetModel();
    for(auto& i : this->local)
    {
        hungry_sniffer::Packet* ptr = const_cast<hungry_sniffer::Packet*>(i.decodedPacket->hasProtocol(protocol));
        if(ptr)
        {
            ptr->updateNameAssociation();
        }
    }
    this->endResetModel();
}
