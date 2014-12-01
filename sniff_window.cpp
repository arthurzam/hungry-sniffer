#include "sniff_window.h"
#include "ui_sniff_window.h"

#include <QMessageBox>
#include <QThread>
#include "devicechoose.h"
#include <unistd.h>
#include <regex>
#include "packetstats.h"

SniffWindow::SniffWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::SniffWindow),
    toNotStop(true),
    isNotExiting(true),
    manageThread(&SniffWindow::managePacketsList, this),
    filterTree(nullptr),
    isCalculatingFilter(false)
{
    ui->setupUi(this);
    connect(ui->actionAbout_Qt, SIGNAL(triggered()), qApp, SLOT(aboutQt()));

    this->setTableHeaders();
    {
        QStringList l;
        l << "Key" << "Value";
        ui->tree_packet->setHeaderLabels(l);
        ui->tree_packet->setColumnCount(2);
    }
}

SniffWindow::~SniffWindow()
{
    this->on_actionStop_triggered();
    this->isNotExiting = false;
    this->manageThread.join();
    delete ui;
}

void SniffWindow::on_actionOpen_triggered()
{
    QStringList filename = QFileDialog::getOpenFileNames(this, tr("Open File"), "", tr("Pcap (*.pcap)"));
    QListIterator<QString> iter(filename);
    while(iter.hasNext())
    {
        QString str = iter.next();
        this->runOfflinePcap(str.toStdString());
    }
}

void SniffWindow::on_tb_filter_textEdited(const QString &arg1)
{
    bool isEnables = !arg1.isEmpty();
    ui->bt_filter_clear->setEnabled(isEnables);
    ui->bt_filter_apply->setEnabled(isEnables);
}

void SniffWindow::on_bt_filter_clear_clicked()
{
    ui->tb_filter->setText("");
    ui->bt_filter_clear->setEnabled(false);
    ui->bt_filter_apply->setEnabled(false);


    delete this->filterTree;
    this->filterTree = nullptr;

    this->isCalculatingFilter = true;

    ui->table_packets->clear();
    ui->table_packets->setRowCount(0);
    this->setTableHeaders();

    for(auto p = this->local.cbegin(); p != this->local.cend(); ++p)
    {
        this->addPacketTable(*p->decodedPacket, p - this->local.cbegin() + 1);
    }
    this->isCalculatingFilter = false;
}

void SniffWindow::on_table_packets_currentItemChanged(QTableWidgetItem *current, QTableWidgetItem*)
{
    if(!current)
        return;
    QTableWidgetItem* item = ui->table_packets->item(current->row(), 0);
    if(item)
        this->setCurrentPacket(this->local.at(item->text().toInt() - 1));
}

void SniffWindow::on_actionSave_triggered()
{
    /*QString filename = QFileDialog::getSaveFileName(this, tr("Save File"), "", tr("Pcap (*.pcap)"));
    d.open(filename.toStdString());
    for(auto i = this->local.cbegin(); i != this->local.cend(); ++i)
    {
        d.dump(*i);
    }
    d.close();*/
}

void SniffWindow::on_actionStop_triggered()
{
    this->toNotStop = false;

    for(auto iter = this->threads.begin(); iter != this->threads.end(); iter = this->threads.erase(iter))
    {
        (*iter)->join();
        delete (*iter);
    }
}

void SniffWindow::on_actionSniff_triggered()
{
    if(getuid() != 0)
    {
        QMessageBox::warning(nullptr, "Not Root", "You should be Root", QMessageBox::StandardButton::Ok);
        return;
    }
    DeviceChoose d;
    d.exec();

    for (QStringList::const_iterator i = d.results.cbegin(); i != d.results.cend(); ++i)
    {
        this->runLivePcap(i->toStdString());
    }
}

void SniffWindow::on_actionTable_triggered()
{
    PacketStats w;
    w.exec();
}

void SniffWindow::on_bt_filter_apply_clicked()
{
    delete this->filterTree;
    this->filterTree = new FilterTree(ui->tb_filter->text().toStdString());

    this->isCalculatingFilter = true;

    ui->table_packets->clear();
    ui->table_packets->setRowCount(0);
    this->setTableHeaders();

    int i = 1;
    for(auto p = this->local.cbegin(); p != this->local.cend(); ++p, ++i)
    {
        if((*this->filterTree).get(&*p->decodedPacket))
        {
            this->addPacketTable(*p->decodedPacket, i);
        }
    }

    this->isCalculatingFilter = false;
}

void SniffWindow::on_actionClear_triggered()
{
    this->isCalculatingFilter = true;

    ui->table_packets->clear();
    ui->table_packets->setRowCount(0);
    this->setTableHeaders();

    this->local.clear();
    baseProtocol->cleanStats();

    this->isCalculatingFilter = false;
}

void SniffWindow::setTableHeaders()
{
    static QStringList list;
    if(list.empty())
        list << "No." << "Protocol" << "Source" << "Destination" << "Info";

    ui->table_packets->setColumnCount(list.size());
    ui->table_packets->setHorizontalHeaderLabels(list);

    ui->table_packets->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
}
