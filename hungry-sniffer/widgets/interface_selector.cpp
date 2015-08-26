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

#include "interface_selector.h"

#include <QAbstractTableModel>
#include <QHeaderView>
#include <QSettings>
#include <QSortFilterProxyModel>

#if defined(Q_OS_WIN)
    #include <winsock2.h>
    #include <windows.h>
#endif
#include <pcap.h>

#include <stdint.h>
#if defined(Q_OS_WIN)
    #include <ws2tcpip.h>
#elif defined(Q_OS_UNIX)
    #include <arpa/inet.h>
    #include <netdb.h>
#endif

class InterfaceModel : public QAbstractTableModel {
    public:
        struct Device {
            bool selected = false;

            QString name;
            QString description;
            QString addr1;
            QString allAddr;

            Device(pcap_if_t* p);
            Device(Device&& other);
        };
        std::vector<Device> list;
        QStringList hidden;

        explicit InterfaceModel(QStringList hidden, QObject* parent = nullptr) :
            QAbstractTableModel(parent), hidden(hidden)
        {
            this->refresh();
        }

        int rowCount(const QModelIndex & = QModelIndex()) const
        {
            return (int)list.size();
        }

        int columnCount(const QModelIndex & = QModelIndex()) const
        {
            return 4;
        }

        QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const;
        bool setData(const QModelIndex& index, const QVariant& value, int role);
        QVariant headerData(int section, Qt::Orientation orientation, int role) const;
        Qt::ItemFlags flags(const QModelIndex &index) const;

        void refresh();
};

InterfaceSelector::InterfaceSelector(QStringList hidden, QWidget* parent) :
    QTableView(parent)
{
    model = new InterfaceModel(hidden, this);
    m_sortFilterProxy = new QSortFilterProxyModel(this);
    m_sortFilterProxy->setSourceModel(model);
    setModel(m_sortFilterProxy);

    setSortingEnabled(true);
    horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    verticalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    setSelectionBehavior(QAbstractItemView::SelectRows);
    sortByColumn(1, Qt::AscendingOrder);
}

QStringList InterfaceSelector::getSelected()
{
    QStringList res;
    for(auto& d : model->list)
        if(d.selected)
            res.append(d.name);
    return res;
}

void InterfaceSelector::select(QStringList selected)
{
    for(const QString& str : selected)
        for(auto& d : model->list)
            if(str == d.name)
                d.selected = true;
}

void InterfaceSelector::refresh()
{
    model->refresh();
}

QVariant InterfaceModel::data(const QModelIndex& index, int role) const
{
    const Device& d = list[index.row()];
    switch(role)
    {
        case Qt::CheckStateRole:
            if(index.column() == 0)
                return (d.selected ? Qt::Checked : Qt::Unchecked);
            break;
        case Qt::ToolTipRole:
            switch(index.column())
            {
                case 2:
                    return d.allAddr;
                case 3:
                    return d.description;
            }
            break;
        case Qt::DisplayRole:
            switch(index.column())
            {
                case 1:
                    return d.name;
                case 2:
                    return d.addr1;
                case 3:
                    return d.description;
            }
            break;
    }
    return QVariant();
}

bool InterfaceModel::setData(const QModelIndex& index, const QVariant& value, int role)
{
    if(role == Qt::CheckStateRole)
    {
        list[index.row()].selected = (value.toInt() == Qt::Checked);
    }
    emit dataChanged(index,index);
    return true;
}

static const QString headers[] = {QStringLiteral(""), QStringLiteral("Name"), QStringLiteral("Address"), QStringLiteral("Description")};

QVariant InterfaceModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if ((role == Qt::DisplayRole) & (orientation == Qt::Horizontal))
    {
        return headers[section];
    }

    return QVariant();
}

Qt::ItemFlags InterfaceModel::flags(const QModelIndex& index) const
{
    if(index.column() == 0 )
        return Qt::ItemIsUserCheckable | Qt::ItemIsEnabled;
    return QAbstractTableModel::flags(index);
}

#if defined(Q_OS_WIN)
bool get_numeric_address(struct sockaddr* sa, char* outbuf, DWORD buflen)
#elif defined(Q_OS_UNIX)
bool get_numeric_address(struct sockaddr* sa, char* outbuf, size_t buflen)
#endif
{
    socklen_t len;
    switch (sa->sa_family)
    {
        case AF_INET:
            len = sizeof(struct sockaddr_in);
            break;
        case AF_INET6:
            len = sizeof(struct sockaddr_in6);
            break;
        default:
            return false;
    }
    if (getnameinfo(sa, len, outbuf, buflen, NULL, 0, NI_NUMERICHOST))
    {
        return false;
    }
    return true;
}

InterfaceModel::Device::Device(pcap_if_t* p) :
    name(p->name), description(p->description)
{
    char buf[NI_MAXHOST];
    for(pcap_addr_t* addr = p->addresses; addr; addr = addr->next)
    {
        if (get_numeric_address(addr->addr, buf, sizeof(buf)))
        {
            if(this->addr1.isEmpty())
                this->addr1 = buf;
            if(!this->allAddr.isEmpty())
                this->allAddr.append('\n');
            this->allAddr.append(buf);
        }
    }
}

InterfaceModel::Device::Device(InterfaceModel::Device&& other) :
    name(std::move(other.name)),
    description(std::move(other.description)),
    addr1(std::move(other.addr1)),
    allAddr(std::move(other.allAddr))
{
}

void InterfaceModel::refresh()
{
    pcap_if_t* devs;
    if(pcap_findalldevs (&devs, NULL))
        return;
    beginResetModel();
    this->list.clear();

    for(pcap_if_t* dev = devs; dev != NULL; dev = dev->next)
    {
        Device d(dev);
        if(!hidden.contains(d.name, Qt::CaseInsensitive))
            this->list.push_back(std::move(d));
    }
    pcap_freealldevs(devs);

    endResetModel();
}
