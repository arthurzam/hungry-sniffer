#include "packetstats.h"
#include "ui_packetstats.h"
#include "sniff_window.h"

#include <QPushButton>
#include <QTimer>
#include <QStandardItemModel>
#include "Protocol.h"

using namespace hungry_sniffer;

PacketStats::PacketStats(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::PacketStats)
{
    ui->setupUi(this);
    timerId = startTimer(1000);

    QPushButton* btRefresh = new QPushButton(QStringLiteral("&Refresh"), ui->buttonBox);
    connect(btRefresh, SIGNAL(clicked()), this, SLOT(setStats()));
    ui->buttonBox->addButton(btRefresh, QDialogButtonBox::ActionRole);

    model = new QStandardItemModel;
    addProtocol(&SniffWindow::core->base, model->invisibleRootItem());
    model->setHorizontalHeaderLabels({QStringLiteral("Protocol"), QStringLiteral("Number")});
    ui->treeView->setModel(model);
    ui->treeView->expandAll();
    ui->treeView->resizeColumnToContents(0);
}

PacketStats::~PacketStats()
{
    killTimer(timerId);
    delete model;
    delete ui;
}

void PacketStats::timerEvent(QTimerEvent*)
{
    setStats();
}

void PacketStats::setStats()
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
