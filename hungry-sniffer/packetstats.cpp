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

#include "packetstats.h"
#include "sniff_window.h"

#include <QPushButton>
#include <QTimer>
#include <QStandardItemModel>
#include <QTreeView>
#include <QBoxLayout>
#include <hs_core.h>

using namespace hungry_sniffer;

PacketStats::PacketStats(QWidget *parent) :
    QDialog(parent),
    treeView(new QTreeView(this))
{
    this->resize(400, 300);
    QVBoxLayout* box = new QVBoxLayout(this);

    this->setWindowTitle(QStringLiteral("Packets Count Stats"));
    treeView->setEditTriggers(QAbstractItemView::NoEditTriggers);
    treeView->setSortingEnabled(true);
    box->addWidget(treeView);

    model = new QStandardItemModel;
    addProtocol(&SniffWindow::core->base, model->invisibleRootItem());
    model->setHorizontalHeaderLabels({QStringLiteral("Protocol"), QStringLiteral("Number")});
    treeView->setModel(model);
    treeView->expandAll();
    treeView->resizeColumnToContents(0);

    timerId = startTimer(1000);
}

PacketStats::~PacketStats()
{
    killTimer(timerId);
    delete model;
}

void PacketStats::timerEvent(QTimerEvent*)
{
    for(node& i : this->list)
    {
        int curr = i.protocol->getPacketsCount();
        if(i.lastValue != curr)
        {
            i.lastValue = curr;
            i.itemValue->setData(curr, Qt::DisplayRole);
        }
    }
}

void PacketStats::addProtocol(const Protocol* protocol, QStandardItem* father)
{
    struct node n;
    n.protocol = protocol;
    n.lastValue = protocol->getPacketsCount();
    n.itemValue = new QStandardItem(QString::number(n.lastValue));
    QStandardItem* first = new QStandardItem(QString::fromStdString(protocol->getName()));
    first->setToolTip(QString::fromStdString(protocol->fullName));
    father->appendRow({first, n.itemValue});
    for(auto& i : protocol->getProtocolsDB())
    {
        addProtocol(&i.second, first);
    }
    this->list.push_back(n);
}
