#include "packetstable_model.h"
#include "Protocol.h"
#include "filter_tree.h"

#include <QBrush>

inline double diffTimeval(const timeval& curr, const timeval& base)
{
    static constexpr double DIVIDE_MILI = 0.000001; // 1 microsec in seconds
    return ((curr.tv_sec - base.tv_sec) + (curr.tv_usec - base.tv_usec) * DIVIDE_MILI);
}

QVariant PacketsTableModel::data(const QModelIndex &index, int role) const
{
    mutex_shownPerRow.lock();
    if(index.row() >= (int)shownPerRow.size())
        return QVariant();
    int row = index.row();
    int number = shownPerRow[index.row()];
    mutex_shownPerRow.unlock();

    switch(role)
    {
        case Qt::ItemDataRole::ToolTipRole:
        case Qt::ItemDataRole::DisplayRole:
            switch(index.column())
            {
                case 0:
                    return QVariant(number);
                case 1:
                    return QString::number(diffTimeval(local[number].rawPacket.time, this->local[0].rawPacket.time), 'f', 6);
                case 2:
                    return QString::fromStdString(local[number].decodedPacket->getName());
                case 3:
                    return QVariant(local[number].rawPacket.len);
                case 4:
                    return QString::fromStdString(local[number].decodedPacket->getSource());
                case 5:
                    return QString::fromStdString(local[number].decodedPacket->getDestination());
                case 6:
                    return (local[number].decodedPacket->isGoodPacket() ? QString::fromStdString(local[number].decodedPacket->getInfo()) : QStringLiteral("Bad Packet"));
            }
            break;
        case Qt::ItemDataRole::BackgroundRole:
            if(!local[number].decodedPacket->isGoodPacket())
            {
                return QBrush(Qt::yellow);
            }
            break;
    }
    return QVariant();
}

QVariant PacketsTableModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    static const QString headers[] = {QStringLiteral("No."), QStringLiteral("Arrival Time"), QStringLiteral("Protocol"), QStringLiteral("Length"),
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

void PacketsTableModel::removeAll()
{
    beginResetModel();
    mutex_shownPerRow.lock();
    this->shownPerRow.clear();
    mutex_shownPerRow.unlock();
    this->local.clear();
    endResetModel();
}

void PacketsTableModel::removeShown()
{
    beginResetModel();
    mutex_shownPerRow.lock();
    int count = 0;
    for(const int& row : shownPerRow)
        local.erase(local.begin() + row - (count++));
    this->shownPerRow.clear();
    mutex_shownPerRow.unlock();
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
    if(shownPerRow.size() == 0)
    {
        return;
    }
    long i = 0; // index in local
    long j = 0; // index in shownPerRow

    long startChangeRow = -1;

    mutex_shownPerRow.lock();
    long shown = shownPerRow[0];
    for(auto& pack : this->local)
    {
        hungry_sniffer::Packet* ptr = const_cast<hungry_sniffer::Packet*>(pack.decodedPacket->hasProtocol(protocol));
        if(ptr)
        {
            ptr->updateNameAssociation();
        }
        if(shown == i)
        {
            if(ptr && startChangeRow == -1)
            {
                startChangeRow = j;
            }
            else if(!ptr && startChangeRow != -1)
            {
                emit dataChanged(index(startChangeRow, 0), index(j, COLUMNS_COUNT - 1));
                startChangeRow = -1;
            }
            shown = shownPerRow[++j];
        }
        i++;
    }
    if(startChangeRow != -1)
    {
        emit dataChanged(index(startChangeRow, 0), index(j, COLUMNS_COUNT - 1));
        startChangeRow = -1;
    }
    mutex_shownPerRow.unlock();
}
