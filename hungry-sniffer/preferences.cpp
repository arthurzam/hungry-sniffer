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

#include "preferences.h"

#include <QDialogButtonBox>
#include <QHeaderView>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QSettings>
#include <QSplitter>
#include <QStackedWidget>
#include <QTreeWidgetItem>
#include <QBoxLayout>

#include <hs_core.h>

std::vector<Preferences::reloadFunc_t> Preferences::reloadFunctions;

using namespace hungry_sniffer::Preference;

static QTreeWidgetItem* getItem(const Preference& pref, QStackedWidget* stack, std::vector<struct Preferences::node_t>& panels, const Preference* show_pref)
{
    QTreeWidgetItem* item = new QTreeWidgetItem(QStringList(QString::fromStdString(pref.name)));
    if(pref.func)
    {
        panels.push_back({pref});
        item->setData(0, Qt::UserRole, (int)(panels.size() - 1));

        if(&pref == show_pref)
        {
            QWidget* widget = panels.back().getWidget(stack);
            stack->setCurrentWidget(widget);
        }
    }
    else
    {
        Qt::ItemFlags flags = item->flags();
        flags &= ~Qt::ItemIsSelectable;
        item->setFlags(flags);
    }
    for(const auto& i : pref.subPreferences)
        item->addChild(getItem(i, stack, panels, show_pref));
    return item;
}

Preferences::Preferences(QWidget* parent, const Preference* show_pref) :
    QDialog(parent)
{
    this->resize(800, 600);
    this->setWindowTitle(QStringLiteral("Preferences"));
    QVBoxLayout* verticalLayout_2 = new QVBoxLayout(this);
    splitter = new QSplitter(Qt::Horizontal, this);

    QWidget* verticalLayoutWidget = new QWidget(splitter);
    QVBoxLayout* verticalLayout = new QVBoxLayout(verticalLayoutWidget);
    verticalLayout->setContentsMargins(0, 0, 0, 0);
    tb_search = new QLineEdit(verticalLayoutWidget);
    verticalLayout->addWidget(tb_search);
    tree_select = new QTreeWidget(verticalLayoutWidget);
    tree_select->header()->setVisible(false);
    verticalLayout->addWidget(tree_select);
    splitter->addWidget(verticalLayoutWidget);

    stackedWidget = new QStackedWidget(splitter);
    splitter->addWidget(stackedWidget);
    verticalLayout_2->addWidget(splitter);

    QDialogButtonBox* buttonBox = new QDialogButtonBox(QDialogButtonBox::Cancel | QDialogButtonBox::Ok | QDialogButtonBox::RestoreDefaults, this);
    connect(buttonBox->button(QDialogButtonBox::RestoreDefaults), SIGNAL(clicked()), this, SLOT(reset_to_defaults()));
    verticalLayout_2->addWidget(buttonBox);

    stackedWidget->addWidget(new QWidget());
    for(const auto& i : HungrySniffer_Core::core->preferences)
    {
        tree_select->addTopLevelItem(getItem(i, stackedWidget, this->nodes, show_pref));
    }
    tree_select->expandAll();

    connect(buttonBox, SIGNAL(accepted()), this, SLOT(accept()));
    connect(buttonBox, SIGNAL(rejected()), this, SLOT(reject()));
    connect(tb_search, SIGNAL(textChanged(QString)), this, SLOT(search_text_changed(QString)));
    connect(tree_select, SIGNAL(currentItemChanged(QTreeWidgetItem*, QTreeWidgetItem*)), this, SLOT(tree_currentItemChanged(QTreeWidgetItem*, QTreeWidgetItem*)));

    splitter->setSizes(QList<int>({175, 599}));
}

void Preferences::accept()
{
    for(struct node_t& node : this->nodes)
        if(node.panel)
            node.panel->save(*settings);
    settings->sync();
    for(reloadFunc_t func : reloadFunctions)
        func(*settings);
    QDialog::accept();
}

void Preferences::tree_currentItemChanged(QTreeWidgetItem* current, QTreeWidgetItem* previous)
{
    if(current && current != previous)
    {
        QVariant var = current->data(0, Qt::UserRole);
        if(!var.isNull())
            stackedWidget->setCurrentWidget(this->nodes[var.toInt()].getWidget(stackedWidget));
    }
}

bool filterEntries(QTreeWidgetItem* item, const QString& str)
{
    bool flag = false;
    if(item->childCount() != 0)
    {
        int end = item->childCount();
        for(int i = 0; i < end; i++)
        {
            flag |= filterEntries(item->child(i), str);
        }
    }
    flag = flag || str.isEmpty() || item->text(0).startsWith(str, Qt::CaseInsensitive);
    item->setHidden(!flag);
    return flag;
}

void Preferences::search_text_changed(const QString& arg1)
{
    int end = tree_select->topLevelItemCount();
    for(int i = 0; i < end; i++)
    {
        filterEntries(tree_select->topLevelItem(i), arg1);
    }
}

void Preferences::reset_to_defaults()
{
    if(QMessageBox::StandardButton::Yes == QMessageBox::question(nullptr,
            QStringLiteral("Reset Preferences"),
            QStringLiteral("Are you sure you want to reset the preferences?\nThis cannot be undone"),
            QMessageBox::StandardButton::Yes | QMessageBox::StandardButton::No))
    {
        settings->clear();
        this->close();
        QMessageBox::information(nullptr, QStringLiteral("Reset Preferences"),
                                 QStringLiteral("Please restart the program to see results"));
    }
}

QWidget* Preferences::node_t::getWidget(QStackedWidget* stack)
{
    if(!panel)
    {
        panel = pref.func(*Preferences::settings);
        stack->addWidget(panel->get());
    }
    return panel->get();
}
