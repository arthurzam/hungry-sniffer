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

#include "packetstable_model.h"
#include "hs_protocol.h"
#include "filter_tree.h"

#include <QBrush>
#include <QThread>

inline double diffTimeval(const struct timeval& curr, const struct timeval& base)
{
    static Q_CONSTEXPR double DIVIDE_MILI = 0.000001; // 1 microsec in seconds
    return ((curr.tv_sec - base.tv_sec) + (curr.tv_usec - base.tv_usec) * DIVIDE_MILI);
}

QVariant PacketsTableModel::data(const QModelIndex &index, int role) const
{
    mutex_shownPerRow.lock();
    if(index.row() >= (int)shownPerRow.size())
        return QVariant();
    int number = this->shownPerRow[index.row()];
    mutex_shownPerRow.unlock();

    const DataStructure::localPacket& pack = this->local[number];
    if(!pack.decodedPacket)
        QThread::msleep(50);
    const hungry_sniffer::Packet* decodedPacket = pack.decodedPacket;

    switch(role)
    {
        case Qt::ItemDataRole::ToolTipRole:
        case Qt::ItemDataRole::DisplayRole:
            switch(index.column())
            {
                case 0:
                    return QVariant(number);
                case 1:
                    return QString::number(diffTimeval(pack.rawPacket.time, this->local[0].rawPacket.time), 'f', 6);
                case 2:
                    return QString::fromStdString(decodedPacket->getName());
                case 3:
                    return QVariant(pack.rawPacket.len);
                case 4:
                    return QString::fromStdString(decodedPacket->getSource());
                case 5:
                    return QString::fromStdString(decodedPacket->getDestination());
                case 6:
                    return (decodedPacket->isGoodPacket() ? QString::fromStdString(decodedPacket->getInfo()) : QStringLiteral("Bad Packet"));
            }
            break;
        case Qt::ItemDataRole::BackgroundRole:
            if(this->showColors)
            {
                unsigned r = 0, b = 0, g = 0;
                for(const hungry_sniffer::Packet* p = decodedPacket; p; p = p->getNext())
                {
                    if(!p->isLocalGood())
                        return QBrush(Qt::yellow);
                    uint32_t color = p->getColor();
                    unsigned a = (color >> 24);
                    if(a != 0) // not fully transperent
                    {
                        unsigned unA = 255 - a;
                        r = (((color & 0x00FF0000) >> 16) * a + unA * r) / 255;
                        g = (((color & 0x0000FF00) >> 8 ) * a + unA * g) / 255;
                        b = (((color & 0x000000FF)      ) * a + unA * b) / 255;
                    }
                }
                if((r | b | g) != 0)
                    return QBrush(QColor(r, g, b));
            }
            break;
    }
    return QVariant();
}

static const QString headers[] = {QStringLiteral("No."), QStringLiteral("Arrival Time"), QStringLiteral("Protocol"), QStringLiteral("Length"),
                                  QStringLiteral("Source"), QStringLiteral("Destination"), QStringLiteral("Info")};

QVariant PacketsTableModel::headerData(int section, Qt::Orientation orientation, int role) const
{
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
        int row = (int)this->shownPerRow.size();
        beginInsertRows(QModelIndex(), row, row);
        this->shownPerRow.push_back((int)this->local.size() - 1);
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
    local.erase(local.begin() + loc);
    for(auto iter = shownPerRow.erase(shownPerRow.begin() + row); iter != shownPerRow.end(); ++iter)
        (*iter)--;
    mutex_shownPerRow.unlock();
    endRemoveRows();
    emit dataChanged(index(row, 0), index((int)shownPerRow.size() - 1, 0));
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
            if((ptr != nullptr) & (startChangeRow == -1))
            {
                startChangeRow = j;
            }
            else if(!((ptr != nullptr) | (startChangeRow == -1)))
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
