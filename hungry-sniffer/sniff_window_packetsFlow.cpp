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

#ifndef Q_COMPILER_INITIALIZER_LISTS
#define Q_COMPILER_INITIALIZER_LISTS
#endif

#include "sniff_window.h"
#include "ui_sniff_window.h"
#include "filter_tree.h"
#include "packetstable_model.h"

#include <QMessageBox>
#include <QThread>
#if defined(Q_OS_WIN)
    #include <winsock2.h>
    #include <windows.h>
#elif defined(Q_OS_UNIX)
#endif
#include <pcap.h>

using namespace DataStructure;

void SniffWindow::runLivePcap(const std::string &name, int maxNumber, QString capture)
{
    static Q_CONSTEXPR unsigned LIVE_TIMEOUT = 1000; // milliseconds
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* pd = pcap_open_live(name.c_str(), 65535, 1, LIVE_TIMEOUT, errbuf);
    if(!pd)
    {
        QMessageBox::warning(nullptr, QStringLiteral("Live Sniffing error"), QString(errbuf), QMessageBox::Ok);
        return;
    }
    ui->statusBar->setLiveSniffing(true);


    struct bpf_program filter;
    pcap_compile(pd, &filter, capture.toUtf8().constData(), 0, 0xffffffff);
    pcap_setfilter(pd, &filter);

    this->toNotStop = true;
    this->threads.push_back(new std::thread(&SniffWindow::runLivePcap_p, this, pd, maxNumber));
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
            ui->statusBar->updateText();
        }
        else if(this->toNotStop & this->threads.empty())
        {
            QThread::msleep(1500);
        }
    }
}

void SniffWindow::runLivePcap_p(pcap* pd, int maxNumber)
{
    RawPacketData raw;
    struct pcap_pkthdr* header;
    const u_char* data;

    int i = 0;
    while(this->toNotStop)
    {
        int returnValue = pcap_next_ex(pd, &header, &data);
        if(returnValue == 0) // timeout
            continue;
        if(returnValue != 1) // error
            break;
        if(header->caplen != header->len)
            break;
        raw.setData(data, header->len);
        raw.time = header->ts;
        this->toAdd.push(std::move(raw));
        i++;
        if(i == maxNumber)
            break;
    }

    pcap_close(pd);
}

static QTreeWidgetItem* getTreeItemFromHeader(const hungry_sniffer::Packet::header_t& header)
{
    QTreeWidgetItem* head;
    if(header.value.length() != 0)
        head = new QTreeWidgetItem(QStringList({QString::fromStdString(header.key), QString::fromStdString(header.value)}));
    else
        head = new QTreeWidgetItem(QStringList(QString::fromStdString(header.key)));

    for(const auto& j : header.subHeaders)
        head->addChild(getTreeItemFromHeader(j));

    head->setData(0, QVariant::UserType, QVariant::fromValue<void*>((void*)&header));
    return head;
}

void SniffWindow::setCurrentPacket(const struct localPacket& pack)
{
    this->selected = const_cast<struct localPacket*>(&pack);
    ui->tree_packet->clear();
    for(const hungry_sniffer::Packet* packet = pack.decodedPacket; packet; packet = packet->getNext())
    {
        const hungry_sniffer::Packet::headers_t& headers = packet->getHeaders();
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
                head->addChild(getTreeItemFromHeader(j));
            }

            ui->tree_packet->addTopLevelItem(head);
        }
    }
    if(pack.rawPacket.additionalHeaders && pack.rawPacket.additionalHeaders->size())
    {
        QTreeWidgetItem* head = new QTreeWidgetItem(QStringList(QStringLiteral("Own Headers")));
        for(auto& i : *pack.rawPacket.additionalHeaders)
            head->addChild(new QTreeWidgetItem(QStringList({i.first, i.second})));
        ui->tree_packet->addTopLevelItem(head);
    }
    ui->tree_packet->expandAll();
    ui->tree_packet->resizeColumnToContents(0);
    ui->tree_packet->collapseAll();

    ui->hexEdit->setSelection(0, 0);
    ui->hexEdit->setData(QByteArray((char*)pack.rawPacket.data, (int)pack.rawPacket.len));
}
