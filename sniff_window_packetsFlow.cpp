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
    while(this->isNotExiting)
    {
        while(this->isCalculatingFilter)
        {
            QThread::msleep(500);
        }
        if(this->toAdd.try_pop(packet))
        {
            this->local.append({packet, std::shared_ptr<EthernetPacket>(new EthernetPacket(packet.get_data(), packet.get_length(), SniffWindow::baseProtocol)), std::time(NULL)});
            const struct localPacket& localPacket = this->local.last();
            if(!filterTree || (*filterTree).get(localPacket.decodedPacket.get()))
                this->addPacketTable(*localPacket.decodedPacket, this->local.size());
        }
        else if(this->threads.empty() && this->toNotStop)
        {
            QThread::msleep(500);
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
            p.manage();
            this->toAdd.push(p);
        }
    }
    catch(const pcappp::PcapError& e)
    {
        QMessageBox::warning(this, "Error", QString::fromLatin1(e.what()));
    }
}

void SniffWindow::runOfflinePcap_p(const std::string &filename)
{
    pcappp::PcapOffline off(filename);
    pcappp::Packet p;
    while(this->toNotStop && off.next(p))
    {
        p.manage();
        this->toAdd.push(p);
    }
}


void SniffWindow::addPacketTable(const hungry_sniffer::Packet &packet, int number)
{
    int row = ui->table_packets->rowCount();
    ui->table_packets->setRowCount(row + 1);
    {
        QTableWidgetItem* item = new QTableWidgetItem();
        item->setData(Qt::DisplayRole, number);
        ui->table_packets->setItem(row, 0, item);
    }
    ui->table_packets->setItem(row, 1, new QTableWidgetItem(QString::fromStdString(packet.getName())));
    ui->table_packets->setItem(row, 2, new QTableWidgetItem(QString::fromStdString(packet.getSource())));
    ui->table_packets->setItem(row, 3, new QTableWidgetItem(QString::fromStdString(packet.getDestination())));
    ui->table_packets->setItem(row, 4, new QTableWidgetItem(QString::fromStdString(packet.getInfo())));
    ui->table_packets->resizeRowToContents(row);
    //ui->table_packets->resizeRowToContents(row);
}

void SniffWindow::setCurrentPacket(const struct localPacket& pack)
{
    hungry_sniffer::Packet::headers_t headers;
    const EthernetPacket& eth = *pack.decodedPacket;
    eth.getHeaders(headers);

    ui->tree_packet->clear();
    for(auto i = headers.cbegin(); i != headers.cend(); ++i)
    {
        QTreeWidgetItem* head = new QTreeWidgetItem((QTreeWidget*)0, QStringList(QString::fromStdString(i->first)));
        auto map = i->second;
        for(auto j = map.cbegin(); j != map.cend(); ++j)
        {
            QStringList str;
            str << QString::fromStdString(j->first) << QString::fromStdString(j->second);
            head->addChild(new QTreeWidgetItem((QTreeWidget*)0, str));
        }

        ui->tree_packet->addTopLevelItem(head);
    }
    ui->tree_packet->expandAll();
    ui->tree_packet->resizeColumnToContents(0);
    ui->tree_packet->collapseAll();

    ui->hexEdit->setData(QByteArray((char*)pack.rawPacket.get_data(), (int)pack.rawPacket.get_length()));
}
