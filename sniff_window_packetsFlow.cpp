#include "sniff_window.h"
#include "ui_sniff_window.h"

#include <QMessageBox>

void SniffWindow::runLivePcap(const std::string &name)
{
    this->toNotStop = true;
    this->threads.push_back(new std::thread(&SniffWindow::runLivePcap_p, this, name));
}

void SniffWindow::runOfflineFile(const std::string &filename)
{
    this->toNotStop = true;
    this->threads.push_back(new std::thread(&SniffWindow::runOfflineOpen_p, this, filename));
}

void SniffWindow::managePacketsList()
{
    RawPacketData packet;
    while(this->isNotExiting)
    {
        while(this->isCalculatingFilter & this->isNotExiting)
        {
            QThread::msleep(1000);
        }
        if(this->toAdd.timeout_move_pop(packet, 4000))
        {
            this->local.push_back({packet, std::make_shared<hungry_sniffer::EthernetPacket>(packet.data, packet.len, &SniffWindow::core->base), std::time(NULL), false});
            struct localPacket& localPacket = this->local.back();
            if((localPacket.isShown = !filterTree || filterTree->get(localPacket.decodedPacket.get())))
                this->addPacketTable(localPacket, this->local.size());
        }
        else if(this->toNotStop & this->threads.empty())
        {
            QThread::msleep(1500);
        }
    }
}

void SniffWindow::runLivePcap_p(const std::string &name)
{
    try {
        pcappp::PcapLive live(name);
        pcappp::Packet p;
        while(this->toNotStop && live.next(p))
        {
            this->toAdd.push(RawPacketData(p));
        }
    }
    catch(const pcappp::PcapError& e)
    {
        QMessageBox::warning(this, QLatin1String("Sniff Error"), QString::fromLatin1(e.what()));
    }
}

static QTableWidgetItem* createItem(QVariant data, bool isGood)
{
    QTableWidgetItem* item = new QTableWidgetItem();
    item->setData(Qt::DisplayRole, data);
    if(!isGood)
        item->setBackground(Qt::yellow);
    return item;
}

inline static QTableWidgetItem* createItem(const std::string& data, bool isGood)
{
    return createItem(QString::fromStdString(data), isGood);
}

void SniffWindow::addPacketTable(const struct localPacket &local, int number)
{
    const hungry_sniffer::Packet &packet = *local.decodedPacket;
    int row = ui->table_packets->rowCount();
    bool isGood = packet.isGoodPacket();

    ui->table_packets->setRowCount(row + 1);

#define SET_ITEM(n, variant) ui->table_packets->setItem(row, n, createItem(variant, isGood))
    SET_ITEM(0, number);
    SET_ITEM(1, (int)(local.rawPacket.time.tv_sec - this->local[0].rawPacket.time.tv_sec));
    SET_ITEM(2, packet.getName());
    SET_ITEM(3, packet.getSource());
    SET_ITEM(4, packet.getDestination());
    SET_ITEM(5, (isGood ? packet.getInfo() : "Bad Packet"));
#undef SET_ITEM

    ui->table_packets->resizeRowToContents(row);
}

void SniffWindow::updateTableShown()
{
    this->isCalculatingFilter = true;

    ui->table_packets->clear();
    ui->table_packets->setRowCount(0);
    this->setTableHeaders();

    int i = 1;
    for(auto& p : this->local)
    {
        if((p.isShown = !(bool)this->filterTree || this->filterTree->get(&*p.decodedPacket)))
        {
            this->addPacketTable(p, i);
        }
        ++i;
    }

    this->isCalculatingFilter = false;
}

void SniffWindow::reloadAllPackets(const hungry_sniffer::Protocol* protocol)
{
    for(auto& i : this->local)
    {
        hungry_sniffer::Packet* ptr = const_cast<hungry_sniffer::Packet*>(i.decodedPacket->hasProtocol(protocol));
        if(ptr)
        {
            ptr->updateNameAssociation();
        }
    }
}

void SniffWindow::setCurrentPacket(const struct localPacket& pack)
{
    this->selected = const_cast<struct localPacket*>(&pack);
    ui->tree_packet->clear();
    for(const hungry_sniffer::Packet* packet = pack.decodedPacket.get(); packet; packet = packet->getNext())
    {
        const hungry_sniffer::Packet::headers_category_t& headers = packet->getHeaders();
        if(!headers.empty())
        {
            QTreeWidgetItem* head = new QTreeWidgetItem(QStringList(QString::fromStdString(packet->getProtocol()->getName())));
            if(!packet->isLocalGood())
                head->setBackgroundColor(0, Qt::yellow);
            for(const auto& j : headers)
            {
                head->addChild(new QTreeWidgetItem(QStringList({QString::fromStdString(j.first), QString::fromStdString(j.second)})));
            }

            ui->tree_packet->addTopLevelItem(head);
        }
    }
    ui->tree_packet->expandAll();
    ui->tree_packet->resizeColumnToContents(0);
    ui->tree_packet->collapseAll();

    ui->hexEdit->setData(QByteArray((char*)pack.rawPacket.data, (int)pack.rawPacket.len));
}
