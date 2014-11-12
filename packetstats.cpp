#include "packetstats.h"
#include "ui_packetstats.h"
#include "sniff_window.h"

#include <QPushButton>

PacketStats::PacketStats(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::PacketStats)
{
    ui->setupUi(this);

    QPushButton* btRefresh = new QPushButton(tr("&Refresh"), ui->buttonBox);
    connect(btRefresh, SIGNAL(clicked()), this, SLOT(setStats()));
    ui->buttonBox->addButton(btRefresh, QDialogButtonBox::ActionRole);

    {
        ui->tableWidget->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
        QStringList l;
        l << "Protocol" << "Number";
        ui->tableWidget->setHorizontalHeaderLabels(l);
    }

    SniffWindow::baseProtocol->getStats(this->table);
    ui->tableWidget->setRowCount(table.size());

    int row;
    for(auto i = table.cbegin(); i != table.cend(); ++i, ++row)
    {
        ui->tableWidget->setItem(row, 0, new QTableWidgetItem(QString::fromStdString(i->first)));
        QTableWidgetItem* item = new QTableWidgetItem();
        item->setData(Qt::DisplayRole, *(i->second));
        ui->tableWidget->setItem(row, 1, item);
    }
}

PacketStats::~PacketStats()
{
    delete ui;
}

void PacketStats::setStats()
{
    int row = 0;
    for(auto i = table.cbegin(); i != table.cend(); ++i, ++row)
    {
        QTableWidgetItem* newItem = ui->tableWidget->item(row, 1);
        if(!newItem)
        {
            newItem = new QTableWidgetItem();
            ui->tableWidget->setItem(row, 1, newItem);
        }
        newItem->setData(Qt::DisplayRole, *(i->second));
    }
}
