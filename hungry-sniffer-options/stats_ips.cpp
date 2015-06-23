#include "stats_ips.h"
#include <netinet/ether.h>
#include <QTableView>
#include <QVBoxLayout>
#include <QHeaderView>
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

void StatsIps::addPacket(const Packet* packet, const timeval&)
{
    static const Protocol* IPv4 = nullptr;
    static const Protocol* IPv6 = nullptr;

    if(IPv4 == nullptr)
    {
        const Protocol* Ethernet = packet->getProtocol();
        IPv4 = Ethernet->getProtocol(ETHERTYPE_IP);
        IPv6 = Ethernet->getProtocol(ETHERTYPE_IPV6);
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
