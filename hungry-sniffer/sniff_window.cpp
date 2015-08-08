#include "sniff_window.h"
#include "ui_sniff_window.h"

#include <QClipboard>
#include <QFileInfo>
#include <QInputDialog>
#include <QMessageBox>
#include <QMimeData>
#include <QPlainTextEdit>
#include <QSettings>
#include <QSortFilterProxyModel>
#include <unistd.h>

#include "devicechoose.h"
#include "history_line_edit.h"
#include "packetstats.h"
#include "preferences.h"
#include "additionalheaderspacket.h"
#include "filter_tree.h"

SniffWindow* SniffWindow::window = nullptr;

SniffWindow::SniffWindow(QWidget* parent) :
    QMainWindow(parent),
    ui(new Ui::SniffWindow),
    model(this),
    statsTable(new PacketStats(this)),
    toNotStop(true),
    isNotExiting(true),
    manageThread(&SniffWindow::managePacketsList, this),
    filterTree(nullptr)
{
    SniffWindow::window = this;
    ui->setupUi(this);
    connect(ui->actionAbout_Qt, SIGNAL(triggered()), qApp, SLOT(aboutQt()));
    ui->table_packets->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    ui->table_packets->horizontalHeader()->setStretchLastSection(true);
    ui->table_packets->verticalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);

    m_sortFilterProxy = new QSortFilterProxyModel(this);
    m_sortFilterProxy->setSourceModel(&model);
    ui->table_packets->setModel(m_sortFilterProxy);

    connect(ui->table_packets->selectionModel(), SIGNAL(currentRowChanged(QModelIndex, QModelIndex)),
            this, SLOT(model_currentRowChanged(QModelIndex, QModelIndex)));
    connect(this, SIGNAL(sig_showMessageBox(QString, QString)), this, SLOT(showMessageBox(QString, QString)));

    ui->tree_packet->setHeaderLabels(QStringList({QStringLiteral("Key"), QStringLiteral("Value")}));
    ui->tree_packet->setColumnCount(2);
    this->setStatsFunctions(core->base);
#ifdef PYTHON_CMD
    initPython();

    QWidget* verticalLayoutWidget = new QWidget(ui->splitter);
    QVBoxLayout* panel_python = new QVBoxLayout(verticalLayoutWidget);
    panel_python->setContentsMargins(0, 0, 0, 0);
    lb_cmd = new QPlainTextEdit(verticalLayoutWidget);
    panel_python->addWidget(lb_cmd);
    QHBoxLayout* horizontalLayout = new QHBoxLayout();
    horizontalLayout->setContentsMargins(0, 0, 0, 0);
    QLabel* img_python = new QLabel(verticalLayoutWidget);
    QSizePolicy sizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
    sizePolicy.setHeightForWidth(img_python->sizePolicy().hasHeightForWidth());
    img_python->setSizePolicy(sizePolicy);
    img_python->setMaximumSize(QSize(32, 32));
    img_python->setPixmap(QPixmap(QStringLiteral(":/icons/python.png")));
    horizontalLayout->addWidget(img_python);
    tb_command = new History_Line_Edit(verticalLayoutWidget);
    connect(tb_command, SIGNAL(returnPressed()), this, SLOT(tb_command_returnPressed()));
    horizontalLayout->addWidget(tb_command);
    panel_python->addLayout(horizontalLayout);
    ui->splitter->addWidget(verticalLayoutWidget);
#else
    ui->action_Python->setVisible(false);
#endif
    setAcceptDrops(true);

    if(core->preferences.empty())
        ui->action_preferences->setVisible(false);

    { // settings block
        QSettings& settings = *Preferences::settings;
        QVariant var;
        settings.beginGroup(QStringLiteral("General"));
        settings.beginGroup(QStringLiteral("UI"));
        bool flag = settings.value(QStringLiteral("splitter_sizes"), false).toBool();
        default_open_location = settings.value(QStringLiteral("default_dir"), QStringLiteral()).toString();
        max_recent_files = settings.value(QStringLiteral("max_recent_files"), 10).toInt();
        settings.endGroup();
        settings.endGroup();

        settings.beginGroup(QStringLiteral("SniffWindow"));
        if(flag)
        {
            var = settings.value(QStringLiteral("splitter_sizes"));
            if(!var.isNull())
            {
                QVariantList l = var.value<QVariantList>();
                QList<int> sizes;
                for(auto i : var.value<QVariantList>())
                    sizes << i.toInt();
                ui->splitter->setSizes(sizes);
            }
        }
        var = settings.value(QStringLiteral("recent_files"));
        if(!var.isNull())
        {
            this->recentFiles_paths = var.toStringList();
        }
        settings.endGroup();
    }

    { // recent files
        recentFiles_actions.resize(max_recent_files, nullptr);
        for(int i = 0; i < max_recent_files; i++)
        {
            QAction* temp = recentFiles_actions[i] = new QAction(ui->menu_recent_files);
            temp->setData(i);
            connect(temp, SIGNAL(triggered(bool)), this, SLOT(recentFile_triggered()));
            ui->menu_recent_files->addAction(temp);
        }
        updateRecentsMenu();
    }
}

SniffWindow::~SniffWindow()
{
    this->isNotExiting = false;
    delete this->statsTable;
#ifdef PYTHON_CMD
    stopPython();
#endif
    this->on_actionStop_triggered();
    this->manageThread.join();
    delete this->filterTree;
    delete ui;
}

void SniffWindow::updateRecentsMenu()
{
    int numRecentFiles = qMin(recentFiles_paths.size(), max_recent_files);
    for(int i = 0; i < numRecentFiles; i++)
    {
        recentFiles_actions[i]->setText(QFileInfo(recentFiles_paths[i]).fileName());
        recentFiles_actions[i]->setToolTip(recentFiles_paths[i]);
        recentFiles_actions[i]->setVisible(true);
    }
    ui->menu_recent_files->setDisabled(numRecentFiles == 0);
    for(int i = numRecentFiles; i < max_recent_files; i++)
        recentFiles_actions[i]->setVisible(false);
}

bool SniffWindow::isRoot()
{
    return !(getuid() && geteuid());
}

void SniffWindow::setStatsFunctions(const hungry_sniffer::Protocol& protocol)
{
    const auto& list = protocol.getStatsWindowDB();
    if(list.size() != 0)
    {
        QMenu* output = new QMenu(QString::fromStdString(protocol.getName()), ui->menuStats);
        for(const auto& window : list)
        {
            QAction* temp = new QAction(QString::fromStdString(window.first), output);
            auto func = window.second;
            connect(temp, &QAction::triggered, [this, func]()
            {
                hungry_sniffer::StatWindow* w = func();
                bool notOnlyShown = !ui->action_only_Shown->isChecked();
                for(const DataStructure::localPacket& i : model.local)
                    if(i.isShown | notOnlyShown)
                        w->addPacket(i.decodedPacket, i.rawPacket.time);
                w->showWindow();
            });
            output->addAction(temp);
        }
        ui->menuStats->addMenu(output);
    }
    for(const auto& i : protocol.getProtocolsDB())
    {
        setStatsFunctions(i.second);
    }
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
    QSettings& settings = *Preferences::settings;
    settings.beginGroup(QStringLiteral("General"));
    settings.beginGroup(QStringLiteral("UI"));
    bool flag = settings.value(QStringLiteral("splitter_sizes"), false).toBool();
    model.showColors = settings.value(QStringLiteral("colored_packets"), true).toBool();
    settings.endGroup();
    settings.endGroup();

    settings.beginGroup(QStringLiteral("SniffWindow"));
    if(flag)
    {
        QVariantList l;
        for(int i : ui->splitter->sizes())
            l << i;
        settings.setValue(QStringLiteral("splitter_sizes"), l);
    }
    settings.setValue(QStringLiteral("recent_files"), this->recentFiles_paths);
    settings.endGroup();

    bar->accept();
}

void SniffWindow::on_tb_filter_textEdited(const QString& arg1)
{
    bool isEnables = !arg1.isEmpty() || (bool)this->filterTree;
    ui->bt_filter_clear->setEnabled(isEnables);
    ui->bt_filter_apply->setEnabled(isEnables);
}

void SniffWindow::on_bt_filter_clear_clicked()
{
    ui->tb_filter->setText("");
    ui->bt_filter_clear->setEnabled(false);
    ui->bt_filter_apply->setEnabled(false);

    FilterTree* filter = this->filterTree.exchange(nullptr);
    delete filter;
    model.rerunFilter(nullptr);
    ui->statusBar->updateText();
}

void SniffWindow::on_actionStop_triggered()
{
    this->toNotStop = false;

    for(const auto& iter : this->threads)
    {
        iter->join();
        delete iter;
    }
    this->threads.clear();
    ui->statusBar->setLiveSniffing(false);
}

void SniffWindow::on_actionSniff_triggered()
{
    DeviceChoose d;
    d.exec();

    QString filter = d.getCaptureFilter();
    int num = d.getMaxCaptureNumber();
    for(const auto& i : d)
    {
        this->runLivePcap(i.toStdString(), num, filter);
    }
}

void SniffWindow::on_action_preferences_triggered()
{
    Preferences().exec();
}

void SniffWindow::on_actionTable_triggered()
{
    this->statsTable->show();
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
    ui->statusBar->updateText();
}

void SniffWindow::on_action_remove_all_triggered()
{
    model.removeAll();
    ui->tree_packet->clear();
    ui->statusBar->updateText();
}

void SniffWindow::on_action_remove_shown_triggered()
{
    model.removeShown();
    ui->tree_packet->clear();
    ui->statusBar->updateText();
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
        ui->statusBar->updateText();
    }
}

void SniffWindow::on_table_packets_customContextMenuRequested(const QPoint& pos)
{
    auto listSelected = ui->table_packets->selectionModel()->selectedIndexes();
    if(listSelected.size() == 0)
        return;
    QModelIndex item = m_sortFilterProxy->mapToSource(listSelected[0]);
    std::vector<QAction*> list;
    QMenu menu;
    int row = model.shownPerRow[item.row()];
    QMenu follow(QStringLiteral("&Follow")), nameSrc(QStringLiteral("Associate Name For &Source")),
          nameDst(QStringLiteral("Associate Name For &Destination")), optionsMenu(QStringLiteral("Special &Options"));

    QAction copyValAction(QStringLiteral("&Copy Value"), nullptr);
    connect(&copyValAction, &QAction::triggered, [this, item] ()
    {
        QApplication::clipboard()->setText(model.data(item, Qt::DisplayRole).toString());
    });
    menu.addAction(&copyValAction);

    QAction removeRowAction(QStringLiteral("&Remove Packet"), nullptr);
    connect(&removeRowAction, &QAction::triggered, [this, row] ()
    {
        model.remove(row);
        ui->statusBar->updateText();
    });
    menu.addAction(&removeRowAction);

    menu.addSeparator();

    const hungry_sniffer::Packet* packet = this->model.local[row].decodedPacket;

    for(const hungry_sniffer::Packet* localPacket = packet; localPacket; localPacket = localPacket->getNext())
    {
        if(localPacket->getProtocol()->getIsConversationEnabeled())
        {
            QAction* action = new QAction(QString::fromStdString(localPacket->getProtocol()->getName()), nullptr);
            connect(action, &QAction::triggered, [this, localPacket]()
            {
                ui->tb_filter->setText(QString::fromStdString(localPacket->getConversationFilterText()));
                this->on_bt_filter_apply_clicked();
                ui->bt_filter_clear->setEnabled(true);
            });
            follow.addAction(action);
            list.push_back(action);
        }
        if(localPacket->getProtocol()->getIsNameService())
        {
            QAction* action = new QAction(QString::fromStdString(localPacket->getProtocol()->getName()), nullptr);
            connect(action, &QAction::triggered, [this, localPacket]()
            {
                this->associateName(localPacket, localPacket->realSource());
            });
            list.push_back(action);
            nameSrc.addAction(action);

            action = new QAction(QString::fromStdString(localPacket->getProtocol()->getName()), nullptr);
            connect(action, &QAction::triggered, [this, localPacket]()
            {
                this->associateName(localPacket, localPacket->realDestination());
            });
            list.push_back(action);
            nameDst.addAction(action);
        }

        auto options = localPacket->getProtocol()->getOptions();
        if(options.size() > 0)
        {
            bool _isNotRoot = !isRoot();
            QMenu* subMenu = new QMenu(QString::fromStdString(localPacket->getProtocol()->getName()), &optionsMenu);
            for(const auto& i : options)
            {
                if(i.isRootRequired & _isNotRoot)
                    continue;
                QAction* action = new QAction(QString::fromStdString(i.name), subMenu);
                auto func = i.func;
                auto protocol = localPacket->getProtocol();
                connect(action, &QAction::triggered, [this, packet, func, protocol]()
                {
                    int res = func(packet, this->optionsDisablerWin.enabledOptions);
                    if((res & hungry_sniffer::Option::ENABLE_OPTION_RETURN_ADDED_DISABLE))
                        this->optionsDisablerWin.refreshOptions();
                    if((res & hungry_sniffer::Option::ENABLE_OPTION_RETURN_RELOAD_TABLE))
                    {
                        model.reloadText(protocol);
                        model.rerunFilter(this->filterTree);
                        ui->statusBar->updateText();
                    }
                });
                subMenu->addAction(action);
                list.push_back(action);
            }
            if(subMenu->actions().size() == 0)
                delete subMenu;
            else
            {
                optionsMenu.addMenu(subMenu);
            }
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

hungry_sniffer::Protocol SniffWindow::infoProtocol(nullptr, "Own Headers");

static QTreeWidgetItem* getRootOfItem(QTreeWidgetItem* item)
{
    QTreeWidgetItem* prev = nullptr;
    for(; item; item = item->parent())
        prev = item;
    return prev;
}

void SniffWindow::on_tree_packet_customContextMenuRequested(const QPoint& pos)
{
    QTreeWidgetItem* item = ui->tree_packet->itemAt(pos);
    if(!item)
        return;
    QTreeWidgetItem* firstLevel = getRootOfItem(item);
    QMenu menu;
    QAction action_copy(QStringLiteral("&Copy Value"), nullptr);
    if(firstLevel != item)
    {
        connect(&action_copy, &QAction::triggered, [item, firstLevel]()
        {
            QApplication::clipboard()->setText(item->text(1));
        });
        menu.addAction(&action_copy);
    }
    QAction action_add(QStringLiteral("&Add Info Header"), nullptr);
    connect(&action_add, &QAction::triggered, [this]()
    {
        hungry_sniffer::Packet& last = const_cast<hungry_sniffer::Packet&>(this->selected->decodedPacket->getLast());
        AdditionalHeadersPacket* pack = static_cast<AdditionalHeadersPacket*>(&last);
        QTreeWidgetItem* info = nullptr;
        if(last.getProtocol() != &infoProtocol)
        {
            last.setNext(pack = new AdditionalHeadersPacket(&infoProtocol));
            info = new QTreeWidgetItem(QStringList(QStringLiteral("Own Headers")));
        }
        else
        {
            info = this->ui->tree_packet->topLevelItem(this->ui->tree_packet->topLevelItemCount() - 1);
        }
        bool ok;
        QString key = QInputDialog::getText(this, QStringLiteral("Header Name"), QStringLiteral("Enter the header name"), QLineEdit::Normal, QStringLiteral(""), &ok);
        if(!ok)
            return;
        QString value = QInputDialog::getText(this, QStringLiteral("Header Value"), QStringLiteral("Enter the header value"), QLineEdit::Normal, QStringLiteral(""), &ok);
        if(!ok)
            return;
        pack->addHeader(key.toStdString(), value.toStdString());

        info->addChild(new QTreeWidgetItem(QStringList({key, value})));
        if(pack != &last)
            ui->tree_packet->addTopLevelItem(info);
    });
    menu.addAction(&action_add);

    QAction action_remove(QStringLiteral("&Remove"), nullptr);
    if(item != firstLevel && firstLevel->text(0) == QStringLiteral("Own Headers"))
    {
        connect(&action_remove, &QAction::triggered, [this, item, firstLevel]()
        {
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
#ifdef PYTHON_CMD
    QList<int> sizes = ui->splitter->sizes();
    sizes[3] = (arg1 ? 1 : 0);
    ui->splitter->setSizes(sizes);
#endif
}

void SniffWindow::on_splitter_splitterMoved(int, int)
{
    QList<int> sizes = ui->splitter->sizes();
    sizes[0] &= -(ui->action_Table->isChecked());
    sizes[1] &= -(ui->action_Tree->isChecked());
    sizes[2] &= -(ui->action_Hex->isChecked());
#ifdef PYTHON_CMD
    sizes[3] &= -(ui->action_Python->isChecked());
#endif
    ui->splitter->setSizes(sizes);
}

void SniffWindow::model_currentRowChanged(QModelIndex newSelection, QModelIndex oldSelection)
{
    int row = m_sortFilterProxy->mapToSource(newSelection).row();
    if(row != m_sortFilterProxy->mapToSource(oldSelection).row())
    {
        int loc = model.shownPerRow[row];
        this->setCurrentPacket(this->model.local[loc]);
        ui->statusBar->updateText(loc);
    }
}

void SniffWindow::showMessageBox(const QString& title, const QString& text)
{
    QMessageBox::warning(nullptr, title, text, QMessageBox::Ok);
}

void SniffWindow::recentFile_triggered()
{
    QAction *action = qobject_cast<QAction *>(sender());
    if (action)
        this->runOfflineFile(recentFiles_paths[action->data().toInt()].toStdString());
}

void SniffWindow::dropEvent(QDropEvent* event)
{
    const QMimeData* mimeData = event->mimeData();
    if (mimeData->hasUrls())
    {
        QList<QUrl> urlList = mimeData->urls();
        for(const auto& i : urlList)
        {
            QString f = i.toLocalFile();
            if(f.endsWith(QStringLiteral(".pcap")) || f.endsWith(QStringLiteral(".hspcap")))
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

void SniffWindow::on_tree_packet_currentItemChanged(QTreeWidgetItem* current, QTreeWidgetItem* previous)
{
    if(!current || previous == current)
        return;

    int row = ui->tree_packet->indexOfTopLevelItem(getRootOfItem(current));
    unsigned start = 0, end;
    const hungry_sniffer::Packet* layer = this->selected->decodedPacket;
    if(layer->isGoodPacket())
    {
        for(int i = 0; i < row; i++)
        {
            start += layer->getLength();
            layer = layer->getNext();
        }
        QVariant var = current->data(0, QVariant::UserType);
        const hungry_sniffer::Packet::header_t* head = (var.isNull() ? nullptr :
                static_cast<const hungry_sniffer::Packet::header_t*>(var.value<void*>()));
        if(head)
        {
            start += head->pos;
            end = start + head->len;
        }
        else
        {
            end = start + layer->getLength();
        }
        ui->hexEdit->setSelection(start, end);
    }
}
