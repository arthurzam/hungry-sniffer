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
    filterFunc(nullptr)
{
    ui->setupUi(this);
    connect(ui->actionAbout_Qt, SIGNAL(triggered()), qApp, SLOT(aboutQt()));

    {
        ui->table_packets->setColumnCount(4);
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
}

void SniffWindow::addPacket(const struct localPacket& packet)
{
    this->addPacketTable(*packet.decodedPacket);
}

void SniffWindow::runLivePcap(const std::string &name)
{
    this->toNotStop = true;
    this->threads.append(new std::thread(&SniffWindow::runLivePcap_p, this, name));
}

void SniffWindow::runOfflinePcap(const std::string &filename)
{
    this->toNotStop = true;
    this->threads.append(new std::thread(&SniffWindow::runOfflinePcap_p, this, filename));
}

void SniffWindow::managePacketsList()
{
    pcappp::Packet packet;
    while(this->isNotExiting)
    {
        if(this->toAdd.try_pop(packet))
        {
            this->local.append({packet, std::shared_ptr<EthernetPacket>(new EthernetPacket(packet.get_data(), packet.get_length(), SniffWindow::baseProtocol)), std::time(NULL)});
            this->addPacket(this->local.last());
        }
        else if(this->threads.empty() && this->toNotStop)
        {
            QThread::msleep(500);
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
            p.manage();
            this->toAdd.push(p);
        }
    }
    catch(const pcappp::PcapError& e)
    {
        QMessageBox::warning(this, "Error", QString::fromLatin1(e.what()));
    }
}

void SniffWindow::runOfflinePcap_p(const std::string &filename)
{
    pcappp::PcapOffline off(filename);
    pcappp::Packet p;
    while(this->toNotStop && off.next(p))
    {
        p.manage();
        this->toAdd.push(p);
    }
}

void SniffWindow::setCurrentPacket(const struct localPacket& pack)
{
    hungry_sniffer::Packet::headers_t headers;
    const EthernetPacket& eth = *pack.decodedPacket;
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

    ui->hexEdit->setData(QByteArray((char*)pack.rawPacket.get_data(), (int)pack.rawPacket.get_length()));
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
    this->setCurrentPacket(this->local.at(ui->table_packets->item(current->row(), 0)->text().toInt() - 1));
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
    int dotPlace = ui->tb_filter->text().indexOf('.');
    QString name = ui->tb_filter->text().mid(0, dotPlace);
    std::string parts = ui->tb_filter->text().mid(dotPlace + 1).toStdString();

    const hungry_sniffer::Protocol* protocol = this->baseProtocol->findProtocol(name.toStdString());
    if(!protocol)
    {
        QMessageBox::warning(this, "No Protcol", "No protocol");
        return;
    }

    hungry_sniffer::Protocol::filterFunction resFunc = nullptr;
    std::smatch smatch;
    for(auto i = protocol->getFilters().cbegin(); i != protocol->getFilters().cend(); ++i)
    {
        if(std::regex_search(parts, smatch, i->first))
        {
            resFunc = i->second;
            break;
        }
    }
    if(!resFunc)
    {
        QMessageBox::warning(this, "No filter", "No filter found to this one");
        return;
    }

}
