#include "sniff_window.h"
#include "ui_sniff_window.h"

#include <QMessageBox>
#include <unistd.h>
#include "devicechoose.h"
#include "packetstats.h"
#include "outputviewer.h"
#include "additionalheaderspacket.h"

SniffWindow* SniffWindow::window = nullptr;

SniffWindow::SniffWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::SniffWindow),
    toNotStop(true),
    isNotExiting(true),
    manageThread(&SniffWindow::managePacketsList, this),
    filterTree(nullptr),
    isCalculatingFilter(false)
{
    SniffWindow::window = this;
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
#ifdef PYTHON_CMD
    initPython();
#else
    on_action_Python_toggled(false);
    ui->action_Python->setVisible(false);
#endif
    setAcceptDrops(true);
}

SniffWindow::~SniffWindow()
{
    this->on_actionStop_triggered();
    this->isNotExiting = false;
    this->manageThread.join();
#ifdef PYTHON_CMD
    stopPython();
#endif
    delete ui;
}

bool SniffWindow::isRoot()
{
    return !(getuid() & geteuid());
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

void SniffWindow::closeEvent(QCloseEvent* bar)
{
    while(this->optionsDisablerWin.enabledOptions.size() != 0)
    {
        if(QMessageBox::StandardButton::Yes == QMessageBox::question(nullptr,
                                                                     tr("Background Options"),
                                                                     tr("There are still background options.\n""Do you want to disable them?"),
                                                                     QMessageBox::StandardButton::Yes | QMessageBox::StandardButton::No))
        {
            this->optionsDisablerWin.exec();
        }
        else
        {
            break;
        }
    }
    bar->accept();
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
    if(!isRoot())
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
        this->reloadAllPackets(localPacket->getProtocol());
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
        QMenu follow(tr("Follow")), nameSrc(tr("Associate Name For Source")),
                nameDst(tr("Associate Name For Destination")), optionsMenu(tr("Special Options"));
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

                auto options = localPacket->getProtocol()->getOptions();
                bool _isNotRoot = !isRoot();
                if(options.size() > 0)
                {
                    QMenu* subMenu = new QMenu(QString::fromStdString(localPacket->getProtocol()->getName()));
                    for(const auto& i : options)
                    {
                        if(i.isRootRequired & _isNotRoot)
                            continue;
                        QAction* action = new QAction(QString::fromStdString(i.name), &optionsMenu);
                        auto func = i.func;
                        auto protocol = localPacket->getProtocol();
                        connect(action, &QAction::triggered, [this, packet, func, protocol]() {
                            int res = func(packet, this->optionsDisablerWin.enabledOptions);
                            if((res & Option::ENABLE_OPTION_RETURN_ADDED_DISABLE))
                                this->optionsDisablerWin.refreshOptions();
                            if((res & Option::ENABLE_OPTION_RETURN_RELOAD_TABLE))
                            {
                                this->reloadAllPackets(protocol);
                                this->updateTableShown();
                            }
                        });
                        subMenu->addAction(action);
                        list.append(action);
                    }
                    if(subMenu->actions().size() == 0)
                        delete subMenu;
                    else
                        optionsMenu.addMenu(subMenu);
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
        if(optionsMenu.actions().size() > 0)
            menu.addMenu(&optionsMenu);
        menu.exec(ui->table_packets->mapToGlobal(pos));
        qDeleteAll(list);
    }
}

void SniffWindow::on_tree_packet_customContextMenuRequested(const QPoint& pos)
{
    static Protocol infoProtocol(nullptr, false, "Own Headers", false, false);
    QTreeWidgetItem* item = ui->tree_packet->itemAt(pos);
    if(!item)
        return;
    QTreeWidgetItem* firstLevel = item->parent();
    if(!firstLevel)
        firstLevel = item;
    QMenu menu;
    QAction action_add(tr("Add Info Header"), nullptr);
    connect(&action_add, &QAction::triggered, [this]() {
        Packet& last = const_cast<Packet&>(this->selected->decodedPacket->getLast());
        AdditionalHeadersPacket* pack = static_cast<AdditionalHeadersPacket*>(&last);
        QTreeWidgetItem* info = nullptr;
        if(last.getProtocol() != &infoProtocol)
        {
            last.setNext(pack = new AdditionalHeadersPacket(&infoProtocol));
            info = new QTreeWidgetItem(QStringList("Own Headers"));
        }
        else
        {
            info = this->ui->tree_packet->topLevelItem(this->ui->tree_packet->topLevelItemCount() - 1);
        }
        bool ok;
        QString key = QInputDialog::getText(this, "Header Name", "Enter the header name", QLineEdit::Normal, "", &ok);
        if(!ok)
            return;
        QString value = QInputDialog::getText(this, "Header Value", "Enter the header value", QLineEdit::Normal, "", &ok);
        if(!ok)
            return;
        pack->addHeader(key.toStdString(), value.toStdString());

        info->addChild(new QTreeWidgetItem(QStringList({key, value})));
        if(pack != &last)
            ui->tree_packet->addTopLevelItem(info);
    });
    menu.addAction(&action_add);

    QAction action_remove(tr("Remove"), nullptr);
    if(item != firstLevel && firstLevel->text(0) == "Own Headers")
    {
        connect(&action_remove, &QAction::triggered, [this, item, firstLevel]() {
            AdditionalHeadersPacket& pack = (AdditionalHeadersPacket&)this->selected->decodedPacket->getLast();
            pack.removeHeader(item->text(0).toStdString());

            delete item;
            if(firstLevel->childCount() == 0)
                delete firstLevel;
        });
        menu.addAction(&action_remove);
    }
    menu.exec(ui->tree_packet->mapToGlobal(pos));
}

void SniffWindow::on_actionDisableOptions_triggered()
{
    if(this->optionsDisablerWin.enabledOptions.size() == 0)
    {
        QMessageBox::warning(nullptr, tr("Empty"), tr("No Background Options running"), QMessageBox::StandardButton::Ok);
    }
    else
    {
        this->optionsDisablerWin.show();
    }
}

void SniffWindow::on_action_Table_toggled(bool arg1)
{
    QList<int> sizes = ui->splitter->sizes();
    sizes[0] = (arg1 ? 1 : 0);
    ui->splitter->setSizes(sizes);
}

void SniffWindow::on_action_Tree_toggled(bool arg1)
{
    QList<int> sizes = ui->splitter->sizes();
    sizes[1] = (arg1 ? 1 : 0);
    ui->splitter->setSizes(sizes);
}

void SniffWindow::on_action_Hex_toggled(bool arg1)
{
    QList<int> sizes = ui->splitter->sizes();
    sizes[2] = (arg1 ? 1 : 0);
    ui->splitter->setSizes(sizes);
}

void SniffWindow::on_action_Python_toggled(bool arg1)
{
    QList<int> sizes = ui->splitter->sizes();
    sizes[3] = (arg1 ? 1 : 0);
    ui->splitter->setSizes(sizes);
}

void SniffWindow::on_splitter_splitterMoved(int, int)
{
    QList<int> sizes = ui->splitter->sizes();
    sizes[0] &= -(ui->action_Table->isChecked());
    sizes[1] &= -(ui->action_Tree->isChecked());
    sizes[2] &= -(ui->action_Hex->isChecked());
    sizes[3] &= -(ui->action_Python->isChecked());
    ui->splitter->setSizes(sizes);
}

void SniffWindow::dropEvent(QDropEvent *event)
{
    const QMimeData* mimeData = event->mimeData();
    if (mimeData->hasUrls())
    {
        QStringList pathList;
        QList<QUrl> urlList = mimeData->urls();
        for(const auto& i : urlList)
        {
            QString f = i.toLocalFile();
            if(f.endsWith(".pcap"))
                this->runOfflinePcap(i.toLocalFile().toStdString());
        }
        event->accept();
    }
}

void SniffWindow::dragEnterEvent(QDragEnterEvent* event)
{
    if (event->mimeData()->hasUrls())
        event->acceptProposedAction();
}
