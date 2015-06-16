#include "packetstats.h"
#include "sniff_window.h"

#include <QPushButton>
#include <QTimer>
#include <QStandardItemModel>
#include <QTreeView>
#include <QVBoxLayout>
#include "Protocol.h"

using namespace hungry_sniffer;

PacketStats::PacketStats(QWidget *parent) :
    QDialog(parent),
    treeView(new QTreeView(this))
{
    this->resize(397, 296);
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
    father->appendRow({first, n.itemValue});
    for(auto& i : protocol->getProtocolsDB())
    {
        addProtocol(&i.second, first);
    }
    this->list.push_back(n);
}
