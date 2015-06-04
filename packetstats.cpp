#include "packetstats.h"
#include "ui_packetstats.h"
#include "sniff_window.h"

#include <QPushButton>
#include <QTimer>
#include <QCloseEvent>
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

    ui->treeWidget->setHeaderLabels(QStringList({QStringLiteral("Protocol"), QStringLiteral("Number")}));

    setStats();
}

PacketStats::~PacketStats()
{
    killTimer(timerId);
    delete ui;
}

void PacketStats::timerEvent(QTimerEvent*)
{
    this->setStats();
}

/**
 * @brief setStatsPerProtocol refrash the stats shown in the tree of protocol under current item
 *
 * @param protocol the protocol to add and take from his children protocols
 * @param currentItem item to where add the sub item of tree
 */
void setStatsPerProtocol(const Protocol *protocol, QTreeWidgetItem* currentItem)
{
    QStringList str;
    str << QString::fromStdString(protocol->getName()) << QString::number(protocol->getPacketsCount());
    QTreeWidgetItem* item = new QTreeWidgetItem(str);
    currentItem->addChild(item);

    for(const auto& i : protocol->getProtocolsDB())
    {
        setStatsPerProtocol(&i.second, item);
    }
}

void PacketStats::setStats()
{
    QStringList str;
    str << QString::fromStdString(SniffWindow::core->base.getName()) << QString::number(SniffWindow::core->base.getPacketsCount());
    QTreeWidgetItem* root = new QTreeWidgetItem(str);

    for(const auto& i : SniffWindow::core->base.getProtocolsDB())
    {
        setStatsPerProtocol(&i.second, root);
    }

    ui->treeWidget->clear();
    ui->treeWidget->addTopLevelItem(root);
    ui->treeWidget->expandAll();
    ui->treeWidget->resizeColumnToContents(0);
    ui->treeWidget->resizeColumnToContents(1);
}
