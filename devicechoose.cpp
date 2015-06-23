#include "devicechoose.h"

#include <QPushButton>
#include <QLabel>
#include <QSortFilterProxyModel>
#include <QVBoxLayout>
#include <QDialogButtonBox>
#include <QTableView>
#include <QHeaderView>

#include <pcap.h>
#include <arpa/inet.h>
#include <netdb.h>

DeviceChoose::DeviceChoose(QWidget* parent) :
    QDialog(parent)
{
    this->resize(417, 279);
    this->setWindowTitle(QStringLiteral("Device Chooser"));
    QVBoxLayout* vbox = new QVBoxLayout(this);

    tableView = new QTableView(this);
    model = new DeviceModel(this);
    m_sortFilterProxy = new QSortFilterProxyModel(this);
    m_sortFilterProxy->setSourceModel(model);
    tableView->setModel(m_sortFilterProxy);
    tableView->setSortingEnabled(true);
    tableView->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    tableView->verticalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    tableView->setSelectionBehavior(QAbstractItemView::SelectRows);
    vbox->addWidget(tableView);

    QDialogButtonBox* buttonBox = new QDialogButtonBox(this);
    buttonBox->setStandardButtons(QDialogButtonBox::Cancel | QDialogButtonBox::Ok);
    QPushButton* btRefresh = new QPushButton(QStringLiteral("&Refresh"), buttonBox);
    connect(btRefresh, SIGNAL(clicked()), model, SLOT(refresh()));
    buttonBox->addButton(btRefresh, QDialogButtonBox::ActionRole);
    connect(buttonBox, SIGNAL(accepted()), this, SLOT(on_buttonBox_accepted()));
    connect(buttonBox, SIGNAL(rejected()), this, SLOT(close()));
    vbox->addWidget(buttonBox);
}

void DeviceChoose::on_buttonBox_accepted()
{
    this->results.clear();
    for(QModelIndex& index : tableView->selectionModel()->selectedRows(0))
    {
        this->results.append(model->data(m_sortFilterProxy->mapToSource(index), Qt::DisplayRole).toString());
    }
    this->close();
}

int get_numeric_address(struct sockaddr* sa, char* outbuf, size_t buflen)
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
            return -1;
    }
    if (getnameinfo(sa, len, outbuf, buflen, NULL, 0, NI_NUMERICHOST))
    {
        return -1;
    }
    return 0;
}

DeviceModel::Device::Device(pcap_if_t* p) :
    name(p->name), description(p->description)
{
    char buf[NI_MAXHOST];
    for(pcap_addr_t* addr = p->addresses; addr; addr = addr->next)
    {
        if (!get_numeric_address(addr->addr, buf, sizeof(buf)))
        {
            if(this->addr1.isEmpty())
                this->addr1 = buf;
            if(!this->allAddr.isEmpty())
                this->allAddr.append('\n');
            this->allAddr.append(buf);
        }
    }
}

DeviceModel::Device::Device(DeviceModel::Device&& other) :
    name(std::move(other.name)),
    description(std::move(other.description)),
    addr1(std::move(other.addr1)),
    allAddr(std::move(other.allAddr))
{
}


QVariant DeviceModel::data(const QModelIndex& index, int role) const
{
    const Device& d = list[index.row()];
    switch(role)
    {
        case Qt::ItemDataRole::ToolTipRole:
            switch(index.column())
            {
                case 1:
                    return d.allAddr;
                case 2:
                    return d.description;
            }
            break;
        case Qt::ItemDataRole::DisplayRole:
            switch(index.column())
            {
                case 0:
                    return d.name;
                case 1:
                    return d.addr1;
                case 2:
                    return d.description;
            }
            break;
    }
    return QVariant();
}

QVariant DeviceModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    static const QString headers[] = {QStringLiteral("Name"), QStringLiteral("Address"), QStringLiteral("Description"),};
    if ((role == Qt::DisplayRole) & (orientation == Qt::Horizontal))
    {
        return headers[section];
    }

    return QVariant();
}

void DeviceModel::refresh()
{
    pcap_if_t* devs;
    if(pcap_findalldevs (&devs, NULL))
        return;
    beginResetModel();
    this->list.clear();
    for(pcap_if_t* dev = devs; dev != NULL; dev = dev->next)
    {
        if(dev->flags & PCAP_IF_UP)
        {
            this->list.push_back(Device(dev));
        }
    }
    pcap_freealldevs(devs);

    endResetModel();
}
