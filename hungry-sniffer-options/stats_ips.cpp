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

#include "stats_ips.h"
#include <QTableView>
#include <QBoxLayout>
#include <QHeaderView>
#include <hs_protocol.h>

using namespace hungry_sniffer;

StatsIps::StatsIps(QWidget *parent) :
    QDialog(parent),
    model(nullptr)
{
    this->resize(400, 300);
    this->setAttribute(Qt::WA_DeleteOnClose);
    this->setWindowTitle(QStringLiteral("IP stats"));

    QVBoxLayout* verticalLayout = new QVBoxLayout(this);
    tableView = new QTableView(this);
    tableView->setModel(&model);
    tableView->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    tableView->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    tableView->verticalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    verticalLayout->addWidget(tableView);

    this->show();
}

void StatsIps::addPacket(const Packet* packet, const timeval&, const uint8_t*, size_t)
{
    static const Protocol* IPv4 = nullptr;
    static const Protocol* IPv6 = nullptr;

    if(IPv4 == nullptr)
    {
        const Protocol* Ethernet = packet->getProtocol();
        IPv4 = Ethernet->getProtocol(0x0800);
        IPv6 = Ethernet->getProtocol(0x86dd);
    }
    const Packet* p = packet->hasProtocol(IPv4);
    if(p == nullptr && (p = packet->hasProtocol(IPv6)) == nullptr)
        return;
    model.add(p->realSource(), 0);
    model.add(p->realDestination(), 1);
}

void StatsIps::showWindow()
{
    model.update();
}

QVariant StatsIpsModel::data(const QModelIndex& index, int role) const
{
    if(role == Qt::ItemDataRole::DisplayRole)
    {
        auto iter = this->ips.cbegin();
        for(uint_fast32_t i = index.row(); i != 0; i--) iter++;
        switch(index.column())
        {
            case 0:
                return QString::fromStdString(iter->first);
            case 1:
                return QVariant(iter->second.src + iter->second.dst);
            case 2:
                return QVariant(iter->second.src);
            case 3:
                return QVariant(iter->second.dst);
        }
    }
    return QVariant();
}

QVariant StatsIpsModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    static const QString headers[] = {QStringLiteral("IP"), QStringLiteral("All"),
                                      QStringLiteral("Source"), QStringLiteral("Destination")};
    if ((role == Qt::DisplayRole) & (orientation == Qt::Horizontal)) {
        return headers[section];
    }

    return QVariant();
}

void StatsIpsModel::add(const std::string& ip, int role)
{
    auto iter = this->ips.find(ip);
    if(iter == this->ips.end())
    {
        this->ips.insert({ip, {1 - role, role}});
    }
    else
    {
        iter->second.src += (1 - role);
        iter->second.dst += role;
    }
}
