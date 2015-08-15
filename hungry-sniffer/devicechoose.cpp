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

#include "devicechoose.h"

#include <QPushButton>
#include <QLabel>
#include <QSortFilterProxyModel>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QDialogButtonBox>
#include <QTableView>
#include <QHeaderView>
#include <QLineEdit>
#include <QSpinBox>

#include <stdint.h>
#if defined(Q_OS_WIN)
    #include <ws2tcpip.h>
#elif defined(Q_OS_UNIX)
    #include <arpa/inet.h>
    #include <netdb.h>
#endif

DeviceChoose::DeviceChoose(QWidget* parent) :
    QDialog(parent)
{
    this->resize(400, 300);
    this->setWindowTitle(QStringLiteral("Device Chooser"));
    QVBoxLayout* vbox = new QVBoxLayout(this);

    tableView = new QTableView();
    model = new DeviceModel(this);
    m_sortFilterProxy = new QSortFilterProxyModel(this);
    m_sortFilterProxy->setSourceModel(model);
    tableView->setModel(m_sortFilterProxy);
    tableView->setSortingEnabled(true);
    tableView->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    tableView->verticalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    tableView->setSelectionBehavior(QAbstractItemView::SelectRows);
    vbox->addWidget(tableView);

    QHBoxLayout* hbox_filter = new QHBoxLayout();
    hbox_filter->addWidget(new QLabel(QStringLiteral("Capture Filter"), this));
    tb_filter = new QLineEdit(this);
    tb_filter->setToolTip(QStringLiteral("Capture Filter in Pcap format"));
    hbox_filter->addWidget(tb_filter);
    vbox->addLayout(hbox_filter);

    QHBoxLayout* hbox_num = new QHBoxLayout();
    hbox_num->addWidget(new QLabel(QStringLiteral("Max Capture Number"), this));
    tb_number = new QSpinBox(this);
    tb_number->setValue(0);
    tb_number->setRange(0, INT_MAX);
    tb_number->setToolTip(QStringLiteral("Maximum number of packets to\n""capture from those interfaces"));
    hbox_num->addWidget(tb_number);
    vbox->addLayout(hbox_num);

    QDialogButtonBox* buttonBox = new QDialogButtonBox(this);
    buttonBox->setStandardButtons(QDialogButtonBox::Cancel | QDialogButtonBox::Ok);
    QPushButton* btRefresh = new QPushButton(QStringLiteral("&Refresh"), buttonBox);
    connect(btRefresh, SIGNAL(clicked()), model, SLOT(refresh()));
    buttonBox->addButton(btRefresh, QDialogButtonBox::ActionRole);
    connect(buttonBox, SIGNAL(accepted()), this, SLOT(on_buttonBox_accepted()));
    connect(buttonBox, SIGNAL(rejected()), this, SLOT(close()));
    vbox->addWidget(buttonBox);
}

QString DeviceChoose::getCaptureFilter() const
{
    return tb_filter->text();
}

int DeviceChoose::getMaxCaptureNumber() const
{
    int val = tb_number->value();
    if(val == 0)
        return -1;
    return val;
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

bool get_numeric_address(struct sockaddr* sa, char* outbuf, size_t buflen)
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

DeviceModel::Device::Device(pcap_if_t* p) :
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

static const QString headers[] = {QStringLiteral("Name"), QStringLiteral("Address"), QStringLiteral("Description")};

QVariant DeviceModel::headerData(int section, Qt::Orientation orientation, int role) const
{
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
        this->list.push_back(Device(dev));
    }
    pcap_freealldevs(devs);

    endResetModel();
}
