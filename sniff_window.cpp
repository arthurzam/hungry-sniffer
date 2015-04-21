#include "sniff_window.h"
#include "ui_sniff_window.h"

#include <QMessageBox>
#include <unistd.h>
#include "devicechoose.h"
#include "packetstats.h"
#include "outputviewer.h"

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
        static QStringList list;
        if(list.empty())
            list << tr("Key") << tr("Value");
        ui->tree_packet->setHeaderLabels(list);
        ui->tree_packet->setColumnCount(list.size());
    }
    this->setOutputFunctions();
}

SniffWindow::~SniffWindow()
{
    this->on_actionStop_triggered();
    this->isNotExiting = false;
    this->manageThread.join();
    delete ui;
}

void SniffWindow::setOutputFunctions()
{
    if(core->outputFunctions.size() == 0)
        return;

    QMenu* output = new QMenu(tr("Output"), this);
    for(const auto& i : core->outputFunctions)
    {
        if(i.second == nullptr)
            continue;

        QAction* temp = new QAction(QString::fromStdString(i.first), this);
        connect(temp, &QAction::triggered, [this, i]() {
            std::stringstream stream;
            for(const auto& p : this->local)
            {
                if(p.isShown)
                    i.second(stream, p.decodedPacket.get());
            }
            OutputViewer* window = new OutputViewer(stream, i.first, this);
            window->show();
        });
        output->addAction(temp);
    }
    ui->menubar->addMenu(output);
}

void SniffWindow::on_actionOpen_triggered()
{
    QStringList filenames = QFileDialog::getOpenFileNames(this, tr("Open File"), "", tr("Pcap (*.pcap)"));
    for(auto& filename : filenames)
    {
        this->runOfflinePcap(filename.toStdString());
    }
}

void SniffWindow::on_tb_filter_textEdited(const QString &arg1)
{
    bool isEnables = !arg1.isEmpty() || (arg1.isEmpty() && (bool)this->filterTree);
    ui->bt_filter_clear->setEnabled(isEnables);
    ui->bt_filter_apply->setEnabled(isEnables);
}

void SniffWindow::on_bt_filter_clear_clicked()
{
    ui->tb_filter->setText("");
    ui->bt_filter_clear->setEnabled(false);
    ui->bt_filter_apply->setEnabled(false);

    this->filterTree = nullptr;

    this->updateTableShown();
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
    if(ui->table_packets->rowCount() == 0)
    {
        QMessageBox::warning(nullptr, tr("Empty Table"), tr("Packets Table is Empty"), QMessageBox::StandardButton::Ok);
        return;
    }
    QString filename = QFileDialog::getSaveFileName(this, tr("Save File"), "", tr("Pcap (*.pcap)"));
    pcappp::Dumper& d = this->firstPcap->get_dumper();
    d.open(filename.toStdString());
    for(auto i = this->local.cbegin(); i != this->local.cend(); ++i)
    {
        d.dump(i->rawPacket);
    }
    d.close();
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
    if(getuid() != 0 && geteuid() != 0)
    {
        QMessageBox::warning(nullptr, tr("Not Root"), tr("You should be Root"), QMessageBox::StandardButton::Ok);
        return;
    }

    DeviceChoose d;
    d.exec();

    for(auto& i : d)
    {
        this->runLivePcap(i.toStdString());
    }
}

void SniffWindow::on_actionTable_triggered()
{
    PacketStats().exec();
}

void SniffWindow::on_bt_filter_apply_clicked()
{
    if(ui->tb_filter->text().isEmpty())
    {
        return this->on_bt_filter_clear_clicked();
    }

    this->filterTree.reset(new FilterTree(ui->tb_filter->text().toStdString()));

    this->updateTableShown();

    ui->bt_filter_apply->setEnabled(false);
}

void SniffWindow::on_actionClear_triggered()
{
    this->isCalculatingFilter = true;

    ui->table_packets->clear();
    ui->table_packets->setRowCount(0);
    this->setTableHeaders();

    this->local.clear();
    core->base.cleanStats();

    this->isCalculatingFilter = false;
}

void SniffWindow::setTableHeaders()
{
    static QStringList list;
    if(list.empty())
        list << tr("No.") << tr("Arrival Time") << tr("Protocol") << tr("Source") << tr("Destination") << tr("Info");

    ui->table_packets->setColumnCount(list.size());
    ui->table_packets->setHorizontalHeaderLabels(list);

    ui->table_packets->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
}

void SniffWindow::associateName(const hungry_sniffer::Packet* localPacket, const std::string& origText)
{
    bool ok;
    QString text = QInputDialog::getText(this, tr("Name Assication"), tr("Associated Name for\n""(%1)").arg(QString::fromStdString(origText)),
                                         QLineEdit::Normal,
                                         QString::fromStdString(localPacket->getProtocol()->getNameAssociated(origText)),
                                         &ok);
    if(ok)
    {
        if(text.isEmpty())
            const_cast<hungry_sniffer::Protocol*>(localPacket->getProtocol())->removeNameAssociation(origText);
        else
            const_cast<hungry_sniffer::Protocol*>(localPacket->getProtocol())->associateName(origText, text.toStdString());
        for(auto& i : this->local)
        {
            hungry_sniffer::Packet* ptr = const_cast<hungry_sniffer::Packet*>(i.decodedPacket->hasProtocol(localPacket->getProtocol()));
            if(ptr)
            {
                ptr->updateNameAssociation();
            }
        }
        this->updateTableShown();
    }
}

void SniffWindow::on_table_packets_customContextMenuRequested(const QPoint &pos)
{
    QTableWidgetItem* item = ui->table_packets->itemAt(pos);
    if(item)
    {
        QList<QAction*> list;
        QMenu menu;
        int row = ui->table_packets->item(item->row(), 0)->text().toInt() - 1;
        QMenu follow(tr("Follow")), nameSrc(tr("Associate Name For Source")), nameDst(tr("Associate Name For Destination"));
        const EthernetPacket* packet = this->local[row].decodedPacket.get();
        {
            const hungry_sniffer::Packet* localPacket = packet;
            while(localPacket)
            {
                if(localPacket->getProtocol()->getIsConversationEnabeled())
                {
                    QAction* action = new QAction(QString::fromStdString(localPacket->getProtocol()->getName()), nullptr);
                    connect(action, &QAction::triggered, [this, localPacket]() {
                        ui->tb_filter->setText(QString::fromStdString(localPacket->getConversationFilterText()));
                        this->on_bt_filter_apply_clicked();
                        ui->bt_filter_clear->setEnabled(true);
                    });
                    follow.addAction(action);
                    list.append(action);
                }
                if(localPacket->getProtocol()->getIsNameService())
                {
                    QAction* action = new QAction(QString::fromStdString(localPacket->getProtocol()->getName()), nullptr);
                    connect(action, &QAction::triggered, [this, localPacket]() {
                        this->associateName(localPacket, localPacket->realSource());
                    });
                    list.append(action);
                    nameSrc.addAction(action);

                    action = new QAction(QString::fromStdString(localPacket->getProtocol()->getName()), nullptr);
                    connect(action, &QAction::triggered, [this, localPacket]() {
                        this->associateName(localPacket, localPacket->realDestination());
                    });
                    list.append(action);
                    nameDst.addAction(action);
                }
                localPacket = localPacket->getNext();
            }
        }
        if(follow.actions().size() > 0)
            menu.addMenu(&follow);
        if(nameDst.actions().size() > 0)
        {
            menu.addMenu(&nameSrc);
            menu.addMenu(&nameDst);
        }
        menu.exec(ui->table_packets->mapToGlobal(pos));
        qDeleteAll(list);
    }
}
