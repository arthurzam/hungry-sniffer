#include "packetstats.h"
#include "ui_packetstats.h"
#include "sniff_window.h"

#include <QPushButton>
#include "Protocol.h"

PacketStats::PacketStats(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::PacketStats)
{
    ui->setupUi(this);

    QPushButton* btRefresh = new QPushButton(tr("&Refresh"), ui->buttonBox);
    connect(btRefresh, SIGNAL(clicked()), this, SLOT(setStats()));
    ui->buttonBox->addButton(btRefresh, QDialogButtonBox::ActionRole);

    {
        QStringList l;
        l << "Protocol" << "Number";
        ui->treeWidget->setHeaderLabels(l);
    }

    setStats();
}

PacketStats::~PacketStats()
{
    delete ui;
}

void PacketStats::setStats()
{
    QStringList str;
    str << QString::fromStdString(SniffWindow::baseProtocol->getName()) << QString::number(SniffWindow::baseProtocol->getPacketsCount());
    QTreeWidgetItem* root = new QTreeWidgetItem(str);

    for(auto i = SniffWindow::baseProtocol->getProtocolsDB().cbegin(); i != SniffWindow::baseProtocol->getProtocolsDB().cend(); ++i)
    {
        this->setStatsPerProtocol(&i->second, root);
    }


    ui->treeWidget->clear();
    ui->treeWidget->addTopLevelItem(root);
    ui->treeWidget->expandAll();
    ui->treeWidget->resizeColumnToContents(0);
    ui->treeWidget->resizeColumnToContents(1);
}

void PacketStats::setStatsPerProtocol(const Protocol *protocol, QTreeWidgetItem* currentItem)
{
    QStringList str;
    str << QString::fromStdString(protocol->getName()) << QString::number(protocol->getPacketsCount());
    QTreeWidgetItem* item = new QTreeWidgetItem(str);
    currentItem->addChild(item);

    for(auto i = protocol->getProtocolsDB().cbegin(); i != protocol->getProtocolsDB().cend(); ++i)
    {
        this->setStatsPerProtocol(&i->second, item);
    }
}
