/*
    Copyright (c) 2015 Zamarin Arthur

    Permission is hereby granted, free of charge, to any person obtaining
    a copy of this software and associated documentation files (the "Software"),
    to deal in the Software without restriction, including without limitation
    the rights to use, copy, modify, merge, publish, distribute, sublicense,
    and/or sell copies of the Software, and to permit persons to whom the Software
    is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
    EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
    OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
    IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
    CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
    TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
    OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef Q_COMPILER_INITIALIZER_LISTS
#define Q_COMPILER_INITIALIZER_LISTS
#endif

#include "sniff_window.h"
#include "ui_sniff_window.h"

#include <QClipboard>
#include <QDesktopServices>
#include <QFileInfo>
#include <QInputDialog>
#include <QMessageBox>
#include <QMimeData>
#include <QPlainTextEdit>
#include <QSettings>
#include <QSortFilterProxyModel>
#if defined(Q_OS_WIN)
#elif defined(Q_OS_UNIX)
    #include <unistd.h>
#endif

#include "about.h"
#include "about_plugins.h"
#include "devicechoose.h"
#include "widgets/history_line_edit.h"
#include "packetstats.h"
#include "preferences.h"
#include "filter_tree.h"

#include <hs_core.h>
#include <hs_stats.h>

SniffWindow* SniffWindow::window = nullptr;

void loadStatsFunctions(const std::list<hungry_sniffer::Stats::StatsNode>& nodes, QMenu& father);

SniffWindow::SniffWindow(QWidget* parent) :
    QMainWindow(parent),
    ui(new Ui::SniffWindow),
    model(),
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
    connect(ui->action_preferences, SIGNAL(triggered()), this, SLOT(open_preference_window()));

    ui->tree_packet->setHeaderLabels(QStringList({QStringLiteral("Key"), QStringLiteral("Value")}));
    ui->tree_packet->setColumnCount(2);
    loadStatsFunctions(HungrySniffer_Core::core->stats, *ui->menuStats);
#ifdef PYTHON_CMD
    QWidget* verticalLayoutWidget = new QWidget(ui->splitter);
    QVBoxLayout* panel_python = new QVBoxLayout(verticalLayoutWidget);
    panel_python->setContentsMargins(0, 0, 0, 0);
    lb_cmd = new QPlainTextEdit(verticalLayoutWidget);
    lb_cmd->setReadOnly(true);
    panel_python->addWidget(lb_cmd);
    QHBoxLayout* horizontalLayout = new QHBoxLayout();
    horizontalLayout->setContentsMargins(0, 0, 0, 0);
    QLabel* img_python = new QLabel(verticalLayoutWidget);
    QSizePolicy sizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
    sizePolicy.setHeightForWidth(img_python->sizePolicy().hasHeightForWidth());
    img_python->setSizePolicy(sizePolicy);
    img_python->setMaximumSize(QSize(32, 32));
    img_python->setPixmap(QPixmap(QStringLiteral(":/icons/python.png")));
#ifndef QT_NO_TOOLTIP
    img_python->setToolTip(PythonThread::getVersionString());
#endif
    horizontalLayout->addWidget(img_python);
    tb_command = new History_Line_Edit(verticalLayoutWidget);
    connect(tb_command, SIGNAL(returnPressed()), this, SLOT(tb_command_returnPressed()));
    horizontalLayout->addWidget(tb_command);
    panel_python->addLayout(horizontalLayout);
    ui->splitter->addWidget(verticalLayoutWidget);

    this->py_checkCommand.reset();
    connect(this, SIGNAL(sig_appendToCmd(QString)), this, SLOT(lb_cmd_appendString(QString)));
    connect(this, SIGNAL(sig_clearCmd()), this, SLOT(lb_cmd_clear()));
    python_thread.start();
#else
    ui->action_Python->setVisible(false);
#endif
    setAcceptDrops(true);

    if(HungrySniffer_Core::core->preferences.empty())
        ui->action_preferences->setVisible(false);

    { // settings block
        QSettings& settings = *Preferences::settings;
        QVariant var;
        settings.beginGroup(QStringLiteral("General"));
        settings.beginGroup(QStringLiteral("UI"));
        bool flag = settings.value(QStringLiteral("splitter_sizes"), false).toBool();
        default_open_location = settings.value(QStringLiteral("default_dir")).toString();
        max_recent_files = settings.value(QStringLiteral("max_recent_files"), 10).toInt();
        model.showColors = settings.value(QStringLiteral("colored_packets"), true).toBool();
        settings.endGroup();
        settings.endGroup();

        settings.beginGroup(QStringLiteral("SniffWindow"));
        if(flag)
        {
            var = settings.value(QStringLiteral("splitter_sizes"));
            if(!var.isNull())
            {
                QList<int> sizes;
                QVariantList list = var.value<QVariantList>();
                for(const auto& i : list)
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
    python_thread.quit();
#endif
    this->on_actionStop_triggered();
    this->manageThread.join();
    delete &*this->filterTree;
    delete ui;
}

void SniffWindow::updateRecentsMenu()
{
    int numRecentFiles = qMin(recentFiles_paths.size(), max_recent_files);
    int diff = max_recent_files - (int)recentFiles_actions.size();
    if(diff != 0)
    {
        if(diff > 0)
        {
            int i = (int)recentFiles_actions.size();
            recentFiles_actions.resize(max_recent_files);
            for(; i < max_recent_files; i++)
            {
                QAction* temp = recentFiles_actions[i] = new QAction(ui->menu_recent_files);
                temp->setData(i);
                connect(temp, SIGNAL(triggered(bool)), this, SLOT(recentFile_triggered()));
                ui->menu_recent_files->addAction(temp);
            }
        }
        else
        {
            for(unsigned i = max_recent_files; i < recentFiles_actions.size(); i++)
                delete recentFiles_actions[i];
            recentFiles_actions.resize(max_recent_files);
        }
    }

    for(int i = 0; i < numRecentFiles; i++)
    {
        recentFiles_actions[i]->setText(QFileInfo(recentFiles_paths[i]).fileName());
#ifndef QT_NO_TOOLTIP
        recentFiles_actions[i]->setToolTip(recentFiles_paths[i]);
#endif
        recentFiles_actions[i]->setVisible(true);
    }
    ui->menu_recent_files->setDisabled(numRecentFiles == 0);
    for(int i = numRecentFiles; i < max_recent_files; i++)
        recentFiles_actions[i]->setVisible(false);
}

bool SniffWindow::isRoot()
{
#if defined(Q_OS_WIN)
    return false;
#elif defined(Q_OS_UNIX)
    return !(getuid() && geteuid());
#endif
}

void loadStatsFunctions(const std::list<hungry_sniffer::Stats::StatsNode>& nodes, QMenu& father)
{
    for(const hungry_sniffer::Stats::StatsNode& i : nodes)
    {
        if(i.subNodes.size() == 0 && i.func)
        {
            QAction* action = new QAction(QString::fromStdString(i.name), SniffWindow::window);
            action->setData(QVariant::fromValue<void*>((void*)i.func));
            QObject::connect(action, SIGNAL(triggered()), SniffWindow::window, SLOT(open_stats_window()));
            father.addAction(action);
        }
        else
        {
            QMenu* menu = new QMenu(QString::fromStdString(i.name), SniffWindow::window);
            loadStatsFunctions(i.subNodes, *menu);
            father.addMenu(menu);
        }
    }
}

void SniffWindow::closeEvent(QCloseEvent* bar)
{
    while(this->optionsDisablerWin.enabledOptions.size() != 0)
    {
        if(QMessageBox::StandardButton::Yes == QMessageBox::question(nullptr,
                QStringLiteral("Background Options"),
                QStringLiteral("There are still background options.\nDo you want to disable them?"),
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
    bool isEnables = !arg1.isEmpty() || &*this->filterTree;
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

void SniffWindow::on_action_about_triggered()
{
    (new About(this))->show();
}

void SniffWindow::on_action_about_plugins_triggered()
{
    AboutPlugins::window->show();
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
                                         QStringLiteral("Associated Name for\n(%1)").arg(QString::fromStdString(origText)),
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

    QMenu menu_copy(QStringLiteral("&Copy"));

    QAction copyCellAction(QStringLiteral("&Cell"), nullptr);
    copyCellAction.setData(model.data(item, Qt::DisplayRole).toString());
    connect(&copyCellAction, SIGNAL(triggered()), this, SLOT(copy_to_clipboard()));
    menu_copy.addAction(&copyCellAction);

    menu_copy.addSeparator();

    QAction copyBase64Action(QStringLiteral("Data as &Base64"), nullptr);
    copyBase64Action.setData(QByteArray(this->selected->rawPacket.data, this->selected->rawPacket.len).toBase64());
    connect(&copyBase64Action, SIGNAL(triggered()), this, SLOT(copy_to_clipboard()));
    menu_copy.addAction(&copyBase64Action);

    QAction copyHexAction(QStringLiteral("Data as &Hex"), nullptr);
    copyHexAction.setData(QByteArray(this->selected->rawPacket.data, this->selected->rawPacket.len).toHex());
    connect(&copyHexAction, SIGNAL(triggered()), this, SLOT(copy_to_clipboard()));
    menu_copy.addAction(&copyHexAction);

    menu.addMenu(&menu_copy);

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
        QString protocolName = QString::fromStdString(localPacket->getProtocol()->getName()).prepend('&');
        if(localPacket->getProtocol()->getIsConversationEnabeled())
        {
            QAction* action = new QAction(protocolName, nullptr);
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
            QAction* action = new QAction(protocolName, nullptr);
            connect(action, &QAction::triggered, [this, localPacket]()
            {
                this->associateName(localPacket, localPacket->realSource());
            });
            list.push_back(action);
            nameSrc.addAction(action);

            action = new QAction(protocolName, nullptr);
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
            QMenu* subMenu = new QMenu(protocolName, &optionsMenu);
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

    menu.addSeparator();

    QAction action_prefs(QStringLiteral("&Protocol Preferences"), nullptr);
    const hungry_sniffer::Preference::Preference* pr = packet->getLast().getProtocol()->preferencePanel;
    if(pr && pr->func)
    {
        action_prefs.setData(QVariant::fromValue<void*>((void*)pr));
        connect(&action_prefs, SIGNAL(triggered()), this, SLOT(open_preference_window()));
        menu.addAction(&action_prefs);
    }

    menu.exec(ui->table_packets->mapToGlobal(pos));
    qDeleteAll(list);
}

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

    QAction action_collapse(QStringLiteral("C&ollapse All"), nullptr);
    connect(&action_collapse, SIGNAL(triggered()), ui->tree_packet, SLOT(collapseAll()));
    menu.addAction(&action_collapse);

    QAction action_expand(QStringLiteral("&Expand All"), nullptr);
    connect(&action_expand, SIGNAL(triggered()), ui->tree_packet, SLOT(expandAll()));
    menu.addAction(&action_expand);

    menu.addSeparator();

    QAction action_copy(QStringLiteral("&Copy Value"), nullptr);
    QAction action_prefs(QStringLiteral("&Protocol Preferences"), nullptr);
    QAction action_website(QStringLiteral("Protocol Help &Website"), nullptr);
    if(firstLevel == item)
    {
        const hungry_sniffer::Packet* selectedPacket = this->selected->decodedPacket->getNext(ui->tree_packet->indexOfTopLevelItem(firstLevel));
        const hungry_sniffer::Protocol* selectedProtocol = selectedPacket->getProtocol();
        const hungry_sniffer::Preference::Preference* pr = selectedProtocol->preferencePanel;
        if(pr && pr->func)
        {
            action_prefs.setData(QVariant::fromValue<void*>((void*)pr));
            connect(&action_prefs, SIGNAL(triggered()), this, SLOT(open_preference_window()));
            menu.addAction(&action_prefs);
        }
        if(!selectedProtocol->websiteUrl.empty())
        {
            action_website.setData(QString::fromStdString(selectedProtocol->websiteUrl));
            connect(&action_website, SIGNAL(triggered()), this, SLOT(open_url()));
            menu.addAction(&action_website);
        }
    }
    else
    {
        action_copy.setData(item->text(1));
        connect(&action_copy, SIGNAL(triggered()), this, SLOT(copy_to_clipboard()));
        menu.addAction(&action_copy);
    }
    QAction action_add(QStringLiteral("&Add Info Header"), nullptr);
    connect(&action_add, SIGNAL(triggered()), this, SLOT(tree_add_info_header()));
    menu.addAction(&action_add);

    QAction action_remove(QStringLiteral("&Remove"), nullptr);
    if(item != firstLevel && firstLevel->text(0) == QStringLiteral("Own Headers"))
    {
        action_copy.setData(QVariant::fromValue<void*>(item));
        connect(&action_remove, SIGNAL(triggered()), this, SLOT(tree_remove_info_header()));
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
#define BOOL_TO_SIZE(flag, size) size = (flag ? (size | 1) : 0)
    QList<int> sizes = ui->splitter->sizes();
    BOOL_TO_SIZE(ui->action_Table->isChecked(), sizes[0]);
    BOOL_TO_SIZE(ui->action_Tree->isChecked(), sizes[1]);
    BOOL_TO_SIZE(ui->action_Hex->isChecked(), sizes[2]);
#ifdef PYTHON_CMD
    BOOL_TO_SIZE(ui->action_Python->isChecked(), sizes[3]);
#endif
    ui->splitter->setSizes(sizes);
#undef BOOL_TO_SIZE
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

void SniffWindow::recentFile_triggered()
{
    QAction* action = qobject_cast<QAction *>(sender());
    if (action)
        this->runOfflineFile(recentFiles_paths[action->data().toInt()].toStdString());
}

void SniffWindow::copy_to_clipboard()
{
    QAction* action = qobject_cast<QAction*>(sender());
    if (action)
        QApplication::clipboard()->setText(action->data().toString());
}

void SniffWindow::open_stats_window()
{
    QAction* action = qobject_cast<QAction*>(sender());
    if (!action) return;
    hungry_sniffer::Stats::statInitFunction func = (hungry_sniffer::Stats::statInitFunction)action->data().value<void*>();
    hungry_sniffer::Stats::StatWindow* w = func();
    bool notOnlyShown = !ui->action_only_Shown->isChecked();
    for(const DataStructure::localPacket& i : model.local)
        if(i.isShown | notOnlyShown)
            w->addPacket(i.decodedPacket, i.rawPacket.time, (const uint8_t*)i.rawPacket.data, i.rawPacket.len);
    w->showWindow();
}

void SniffWindow::tree_add_info_header()
{
    auto addHeaders = this->selected->rawPacket.additionalHeaders;
    QTreeWidgetItem* info = nullptr;
    if(addHeaders && addHeaders->size() != 0)
    {
        info = this->ui->tree_packet->topLevelItem(this->ui->tree_packet->topLevelItemCount() - 1);
    }
    else
    {
        addHeaders = this->selected->rawPacket.additionalHeaders = new std::vector<std::pair<QString, QString>>();
        info = new QTreeWidgetItem(QStringList(QStringLiteral("Own Headers")));
    }
    bool ok;
    QString key = QInputDialog::getText(this, QStringLiteral("Header Name"), QStringLiteral("Enter the header name"), QLineEdit::Normal, QStringLiteral(""), &ok);
    if(!ok)
        return;
    QString value = QInputDialog::getText(this, QStringLiteral("Header Value"), QStringLiteral("Enter the header value"), QLineEdit::Normal, QStringLiteral(""), &ok);
    if(!ok)
        return;
    addHeaders->push_back({key, value});

    info->addChild(new QTreeWidgetItem(QStringList({key, value})));
    if(addHeaders->size() == 1)
        ui->tree_packet->addTopLevelItem(info);
}

void SniffWindow::tree_remove_info_header()
{
    QAction* action = qobject_cast<QAction*>(sender());
    if (!action) return;
    QTreeWidgetItem* item = (QTreeWidgetItem*)action->data().value<void*>();

    QTreeWidgetItem* root = this->ui->tree_packet->topLevelItem(this->ui->tree_packet->topLevelItemCount() - 1);
    auto headers = this->selected->rawPacket.additionalHeaders;
    headers->erase(headers->begin() + root->indexOfChild(item));
    delete item;
    if(headers->size() == 0)
    {
        delete this->ui->tree_packet->topLevelItem(this->ui->tree_packet->topLevelItemCount() - 1);
    }
}

void SniffWindow::open_preference_window()
{
    hungry_sniffer::Preference::Preference* pref = nullptr;
    QAction* action = qobject_cast<QAction*>(sender());
    if (action)
    {
        QVariant var = action->data();
        if(!var.isNull())
            pref = (hungry_sniffer::Preference::Preference*)var.value<void*>();
    }
    (new Preferences(this, pref))->show();
}

void SniffWindow::open_url()
{
    QAction* action = qobject_cast<QAction*>(sender());
    if (action)
        QDesktopServices::openUrl(QUrl(action->data().toString()));
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
    if(this->selected->rawPacket.additionalHeaders && row == ui->tree_packet->topLevelItemCount() - 1)
        return;
    unsigned start = 0, end;
    const hungry_sniffer::Packet* layer = this->selected->decodedPacket;
    if(layer->isLocalGood())
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
#ifdef PYTHON_CMD
void SniffWindow::lb_cmd_appendString(QString str)
{
    lb_cmd->moveCursor(QTextCursor::End);
    lb_cmd->textCursor().insertHtml(str);
    lb_cmd->moveCursor(QTextCursor::End);
}

void SniffWindow::lb_cmd_clear()
{
    lb_cmd->clear();
}
#endif
