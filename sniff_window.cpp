#include "sniff_window.h"
#include "ui_sniff_window.h"

#include <QMessageBox>
#include <unistd.h>
#include "devicechoose.h"
#include "packetstats.h"
#include "outputviewer.h"
#include "additionalheaderspacket.h"
#include "filter_tree.h"
#include "packetstable_model.h"

SniffWindow* SniffWindow::window = nullptr;

SniffWindow::SniffWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::SniffWindow),
    model(this),
    toNotStop(true),
    isNotExiting(true),
    manageThread(&SniffWindow::managePacketsList, this),
    filterTree(nullptr)
{
    SniffWindow::window = this;
    ui->setupUi(this);
    connect(ui->actionAbout_Qt, SIGNAL(triggered()), qApp, SLOT(aboutQt()));
    ui->table_packets->setModel(&model);
    ui->table_packets->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);

    connect(ui->table_packets->selectionModel(), SIGNAL(currentRowChanged(QModelIndex,QModelIndex)),
            this,SLOT(model_currentRowChanged(QModelIndex,QModelIndex)));

    ui->tree_packet->setHeaderLabels(QStringList({QStringLiteral("Key"), QStringLiteral("Value")}));
    ui->tree_packet->setColumnCount(2);
    this->setOutputFunctions();
#ifdef PYTHON_CMD
    initPython();
#else
    ui->action_Python->setVisible(false);
    ui->action_Python->setChecked(false);
    on_splitter_splitterMoved(0, 0);
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
    delete this->filterTree;
    delete ui;
}

bool SniffWindow::isRoot()
{
    return !(getuid() && geteuid());
}

void SniffWindow::setOutputFunctions()
{
    if(core->outputFunctions.size() == 0)
        return;

    QMenu* output = new QMenu(QStringLiteral("Output"), this);
    for(const auto& i : core->outputFunctions)
    {
        if(i.second == nullptr)
            continue;

        QAction* temp = new QAction(QString::fromStdString(i.first), this);
        connect(temp, &QAction::triggered, [this, i]() {
            std::stringstream stream;
            for(const auto& p : this->model.local)
            {
                if(p.isShown)
                    i.second(stream, p.decodedPacket);
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
                                                                     QStringLiteral("Background Options"),
                                                                     QStringLiteral("There are still background options.\n""Do you want to disable them?"),
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
    model.rerunFilter(nullptr);
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
        QMessageBox::warning(nullptr, QStringLiteral("Not Root"), QStringLiteral("You should be Root"), QMessageBox::StandardButton::Ok);
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

    FilterTree* filter = this->filterTree.exchange(new FilterTree(ui->tb_filter->text().toStdString()));
    delete filter;
    model.rerunFilter(this->filterTree);

    ui->bt_filter_apply->setEnabled(false);
}

void SniffWindow::on_actionClear_triggered()
{
    model.clear();
}

void SniffWindow::associateName(const hungry_sniffer::Packet* localPacket, const std::string& origText)
{
    bool ok;
    QString text = QInputDialog::getText(this, QStringLiteral("Name Assication"),
                                         QStringLiteral("Associated Name for\n""(%1)").arg(QString::fromStdString(origText)),
                                         QLineEdit::Normal,
                                         QString::fromStdString(localPacket->getProtocol()->getNameAssociated(origText)),
                                         &ok);
    if(ok)
    {
        hungry_sniffer::Protocol* p = const_cast<hungry_sniffer::Protocol*>(localPacket->getProtocol());
        if(text.isEmpty())
            p->removeNameAssociation(origText);
        else
            p->associateName(origText, text.toStdString());
        model.reloadText(localPacket->getProtocol());
        model.rerunFilter(this->filterTree);
    }
}

void SniffWindow::on_table_packets_customContextMenuRequested(const QPoint &pos)
{
    auto listSelected = ui->table_packets->selectionModel()->selectedIndexes();
    if(listSelected.size() == 0)
        return;
    QModelIndex& item = listSelected[0];
    {
        QList<QAction*> list;
        QMenu menu;
        int row = model.shownPerRow[item.row()];
        QMenu follow(QStringLiteral("Follow")), nameSrc(QStringLiteral("Associate Name For Source")),
                nameDst(QStringLiteral("Associate Name For Destination")), optionsMenu(QStringLiteral("Special Options"));

        QAction copyValAction(QStringLiteral("Copy Value"), nullptr);
        connect(&copyValAction, &QAction::triggered, [this, item] () {
            QApplication::clipboard()->setText(this->model.data(item).toString());
        });
        menu.addAction(&copyValAction);

        QAction removeRowAction(QStringLiteral("Remove Packet"), nullptr);
        connect(&removeRowAction, &QAction::triggered, [this, item] () {
            model.remove(item.row());
        });
        menu.addAction(&removeRowAction);

        menu.addSeparator();

        const hungry_sniffer::Packet* packet = this->model.local[row].decodedPacket;
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
                    QMenu* subMenu = new QMenu(QString::fromStdString(localPacket->getProtocol()->getName()), &optionsMenu);
                    for(const auto& i : options)
                    {
                        if(i.isRootRequired & _isNotRoot)
                            continue;
                        QAction* action = new QAction(QString::fromStdString(i.name), subMenu);
                        auto func = i.func;
                        auto protocol = localPacket->getProtocol();
                        connect(action, &QAction::triggered, [this, packet, func, protocol]() {
                            int res = func(packet, this->optionsDisablerWin.enabledOptions);
                            if((res & hungry_sniffer::Option::ENABLE_OPTION_RETURN_ADDED_DISABLE))
                                this->optionsDisablerWin.refreshOptions();
                            if((res & hungry_sniffer::Option::ENABLE_OPTION_RETURN_RELOAD_TABLE))
                            {
                                model.reloadText(protocol);
                                model.rerunFilter(this->filterTree);
                            }
                        });
                        subMenu->addAction(action);
                        list.append(action);
                    }
                    if(subMenu->actions().size() == 0)
                        delete subMenu;
                    else
                    {
                        optionsMenu.addMenu(subMenu);
                    }
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

hungry_sniffer::Protocol SniffWindow::infoProtocol(nullptr, false, "Own Headers", false, false);

void SniffWindow::on_tree_packet_customContextMenuRequested(const QPoint& pos)
{
    QTreeWidgetItem* item = ui->tree_packet->itemAt(pos);
    if(!item)
        return;
    QTreeWidgetItem* firstLevel = item->parent();
    if(!firstLevel)
        firstLevel = item;
    QMenu menu;
    QAction action_add(QStringLiteral("Add Info Header"), nullptr);
    connect(&action_add, &QAction::triggered, [this]() {
        hungry_sniffer::Packet& last = const_cast<hungry_sniffer::Packet&>(this->selected->decodedPacket->getLast());
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

    QAction action_remove(QStringLiteral("Remove"), nullptr);
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
        QMessageBox::warning(nullptr, QStringLiteral("Empty"), QStringLiteral("No Background Options running"),
                             QMessageBox::StandardButton::Ok);
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

void SniffWindow::model_currentRowChanged(QModelIndex newSelection, QModelIndex oldSelection)
{
    int row = newSelection.row();
    if(row != oldSelection.row())
    {
        int loc = model.shownPerRow[row];
        if(loc != -1)
            this->setCurrentPacket(this->model.local[loc]);
    }
}

void SniffWindow::dropEvent(QDropEvent *event)
{
    const QMimeData* mimeData = event->mimeData();
    if (mimeData->hasUrls())
    {
        QList<QUrl> urlList = mimeData->urls();
        for(const auto& i : urlList)
        {
            QString f = i.toLocalFile();
            if(f.endsWith(".pcap"))
                this->runOfflineFile(i.toLocalFile().toStdString());
        }
        event->accept();
    }
}

void SniffWindow::dragEnterEvent(QDragEnterEvent* event)
{
    if (event->mimeData()->hasUrls())
        event->acceptProposedAction();
}
