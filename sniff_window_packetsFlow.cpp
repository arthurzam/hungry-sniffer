#include "sniff_window.h"
#include "ui_sniff_window.h"

#include <QMessageBox>
#include <QThread>
#include "devicechoose.h"
#include <unistd.h>
#include <regex>
#include "packetstats.h"


void SniffWindow::runLivePcap(const std::string &name)
{
    this->toNotStop = true;
    this->threads.append(new std::thread(&SniffWindow::runLivePcap_p, this, name));
}

void SniffWindow::runOfflinePcap(const std::string &filename)
{
    this->toNotStop = true;
    this->threads.append(new std::thread(&SniffWindow::runOfflinePcap_p, this, filename));
}

void SniffWindow::managePacketsList()
{
    pcappp::Packet packet;
    try {
        while(this->isNotExiting)
        {
            while(this->isCalculatingFilter)
            {
                QThread::msleep(500);
            }
            if(this->toAdd.try_pop(packet))
            {
                this->local.append({packet, std::make_shared<EthernetPacket>(packet.get_data(), packet.get_length(), &SniffWindow::core->base), std::time(NULL), false});
                struct localPacket& localPacket = this->local.last();
                if((localPacket.isShown = !filterTree || (*filterTree).get(localPacket.decodedPacket.get())))
                    this->addPacketTable(localPacket, this->local.size());
            }
            else if(this->threads.empty() && this->toNotStop)
            {
                QThread::msleep(500);
            }
        }
    } catch (...) {
        qDebug() << "error";
    }
}

void SniffWindow::runLivePcap_p(const std::string &name)
{
    try {
        std::shared_ptr<pcappp::PcapLive> live = std::make_shared<pcappp::PcapLive>(name);
        if(!this->firstPcap)
            this->firstPcap = live;
        pcappp::Packet p;
        while(this->toNotStop && live->next(p))
        {
            p.manage();
            this->toAdd.push(p);
        }
    }
    catch(const pcappp::PcapError& e)
    {
        QMessageBox::warning(this, tr("Sniff Error"), QString::fromLatin1(e.what()));
    }
}

void SniffWindow::runOfflinePcap_p(const std::string &filename)
{
    std::shared_ptr<pcappp::PcapOffline> off = std::make_shared<pcappp::PcapOffline>(filename);
    if(!this->firstPcap)
        this->firstPcap = off;
    pcappp::Packet p;
    while(this->toNotStop && off->next(p))
    {
        p.manage();
        this->toAdd.push(p);
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
    SET_ITEM(1, (int)(local.rawPacket.get_seconds() - this->local[0].rawPacket.get_seconds()));
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

void SniffWindow::setCurrentPacket(const struct localPacket& pack)
{
    hungry_sniffer::Packet::headers_t headers;
    pack.decodedPacket->getHeaders(headers);

    ui->tree_packet->clear();
    for(const auto& i : headers)
    {
        QTreeWidgetItem* head = new QTreeWidgetItem(QStringList(QString::fromStdString(i.first)));
        for(const auto& j : i.second)
        {
            head->addChild(new QTreeWidgetItem(QStringList({QString::fromStdString(j.first), QString::fromStdString(j.second)})));
        }

        ui->tree_packet->addTopLevelItem(head);
    }
    ui->tree_packet->expandAll();
    ui->tree_packet->resizeColumnToContents(0);
    ui->tree_packet->collapseAll();

    ui->hexEdit->setData(QByteArray((char*)pack.rawPacket.get_data(), (int)pack.rawPacket.get_length()));
}
