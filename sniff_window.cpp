#include "sniff_window.h"
#include "ui_sniff_window.h"

#include <QMessageBox>
#include <QThread>
#include "EthernetPacket.h"
#include "devicechoose.h"
#include <unistd.h>

SniffWindow::SniffWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::SniffWindow)
{
    ui->setupUi(this);
    connect(ui->actionAbout_Qt, SIGNAL(triggered()), qApp, SLOT(aboutQt()));

    ui->table_packets->setColumnCount(4);
    ui->tree_packet->setColumnCount(2);

    /*QString line = "hello";
    for(int i=0; i<ui->table_packets->rowCount(); i++)
    {
        for(int j=0; j<ui->table_packets->columnCount(); j++)
        {
            QTableWidgetItem *pCell = ui->table_packets->item(i, j);
            if(!pCell)
            {
                pCell = new QTableWidgetItem;
                ui->table_packets->setItem(i, j, pCell);
            }
            pCell->setText(line);
        }
        QTableWidgetItem* rowHeader = new QTableWidgetItem(QString::number(i + 1));
        ui->table_packets->setVerticalHeaderItem(i, rowHeader);
    }*/
    {
        QStringList l;
        l << "No." << "Protocol" << "Source" << "Destination";
        ui->table_packets->setHorizontalHeaderLabels(l);

        ui->table_packets->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
        //ui->table_packets->resizeRowsToContents();
    }
    {
        QStringList l;
        l << "Key" << "Value";
        ui->tree_packet->setHeaderLabels(l);
    }
}

SniffWindow::~SniffWindow()
{
    this->on_actionStop_triggered();
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
}

void SniffWindow::addPacket(const pcappp::Packet &packet)
{
    // compute packet
    EthernetPacket eth(packet.get_data(), packet.get_length(), SniffWindow::baseProtocol);
    this->addPacketTable(eth);
    //ui->table_packets->setItem(row, 1, new QTableWidgetItem(QString::fromStdString(eth.getName())));

    //this->toAdd.push(packet);
}

void SniffWindow::runLivePcap(const std::string &name)
{
    this->threads.append(new std::thread(&SniffWindow::runLivePcap_p, this, name));
}

void SniffWindow::runOfflinePcap(const std::string &filename)
{
    this->threads.append(new std::thread(&SniffWindow::runOfflinePcap_p, this, filename));
}

void SniffWindow::managePacketsList()
{
    pcappp::Packet packet;
    while(this->toNotStop)
    {
        if(!this->toAdd.empty())
        {
            this->toAdd.pop(packet);
            this->addPacket(packet);
            this->local.append(packet);
        }
        else if(this->threads.size() == 0 && this->toNotStop)
        {
            QThread::sleep(1);
        }
    }
}

void SniffWindow::runLivePcap_p(const std::string &name)
{
    pcappp::PcapLive live(name);
    pcappp::Packet p;
    while(this->toNotStop && live.next(p))
    {
        p.manage();

        this->addPacket(p);
        this->local.append(p);

        //this->toAdd.push(p);
    }
}

void SniffWindow::runOfflinePcap_p(const std::string &filename)
{
    pcappp::PcapOffline off(filename);
    pcappp::Packet p;
    while(this->toNotStop && off.next(p))
    {
        p.manage();

        this->addPacket(p);
        this->local.append(p);

        //this->toAdd.push(p);
    }
}

void SniffWindow::setCurrentPacket(const pcappp::Packet& packet)
{
    hungry_sniffer::Packet::headers_t headers;
    EthernetPacket eth(packet.get_data(), packet.get_length(), SniffWindow::baseProtocol);
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

    ui->hexEdit->setData(QByteArray((char*)packet.get_data(), (int)packet.get_length()));
}

void SniffWindow::addPacketTable(const hungry_sniffer::Packet &packet)
{
    int row = ui->table_packets->rowCount();
    ui->table_packets->setRowCount(row + 1);
    {
        QTableWidgetItem* item = new QTableWidgetItem();
        item->setData(Qt::DisplayRole, row + 1);
        ui->table_packets->setItem(row, 0, item);
    }
    ui->table_packets->setItem(row, 1, new QTableWidgetItem(QString::fromStdString(packet.getName())));
    ui->table_packets->setItem(row, 2, new QTableWidgetItem(QString::fromStdString(packet.getSource())));
    ui->table_packets->setItem(row, 3, new QTableWidgetItem(QString::fromStdString(packet.getDestination())));
    ui->table_packets->resizeRowToContents(row);
    //ui->table_packets->resizeRowToContents(row);
}

void SniffWindow::on_table_packets_currentItemChanged(QTableWidgetItem *current, QTableWidgetItem*)
{
    const pcappp::Packet& packet = this->local.at(ui->table_packets->item(current->row(), 0)->text().toInt() - 1);
    this->setCurrentPacket(packet);
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
    QListIterator<std::thread*> iter(this->threads);
    while(iter.hasNext())
    {
        std::thread* t = iter.next();
        t->join();
        delete t;
    }
    this->threads.clear();
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
