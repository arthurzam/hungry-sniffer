#include "sniff_window.h"
#include "ui_sniff_window.h"
#include "filter_tree.h"
#include "packetstable_model.h"

#include <QMessageBox>
#include <pcap++.h>

using namespace DataStructure;

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
        if(this->toAdd.timeout_move_pop(packet, 4000))
        {
            localPacket p(std::move(packet));
            FilterTree* filter = this->filterTree;
            p.isShown = !filter || filter->get(p.decodedPacket);
            this->model.append(std::move(p));
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

void SniffWindow::setCurrentPacket(const struct localPacket& pack)
{
    this->selected = const_cast<struct localPacket*>(&pack);
    ui->tree_packet->clear();
    for(const hungry_sniffer::Packet* packet = pack.decodedPacket; packet; packet = packet->getNext())
    {
        const hungry_sniffer::Packet::headers_category_t& headers = packet->getHeaders();
        if(!headers.empty())
        {
            QTreeWidgetItem* head = new QTreeWidgetItem(QStringList(QString::fromStdString(packet->getProtocol()->getName())));
            if(!packet->isLocalGood())
            {
                head->setBackgroundColor(0, Qt::yellow);
                head->setBackgroundColor(1, Qt::yellow);
            }
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
