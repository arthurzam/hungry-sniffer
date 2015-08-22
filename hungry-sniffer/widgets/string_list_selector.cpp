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

#include "string_list_selector.h"

#include <QBoxLayout>
#include <QListWidget>
#include <QPushButton>

StringListSelector::StringListSelector(on_add_function_t func, QWidget *parent) : QWidget(parent)
{
    this->adder = func;

    QVBoxLayout* vbox = new QVBoxLayout(this);
    QHBoxLayout* hbox_bts = new QHBoxLayout();
    QPushButton* bt_add = new QPushButton(QStringLiteral("Add"), this);
    connect(bt_add, SIGNAL(clicked()), this, SLOT(bt_add_clicked()));
    hbox_bts->addWidget(bt_add);
    QPushButton* bt_remove = new QPushButton(QStringLiteral("Remove"), this);
    connect(bt_remove, SIGNAL(clicked()), this, SLOT(bt_remove_clicked()));
    hbox_bts->addWidget(bt_remove);
    vbox->addLayout(hbox_bts);

    this->list = new QListWidget(this);
    this->list->setSelectionMode(QAbstractItemView::MultiSelection);
    vbox->addWidget(this->list);
}

QStringList StringListSelector::getItems()
{
    QStringList l;
    for(int i = 0; i < list->count(); i++)
        l.append(list->item(i)->text());
    return l;
}

void StringListSelector::addItems(const QStringList& items)
{
    for(const QString& str : items)
        this->list->addItem(str);
}

void StringListSelector::bt_add_clicked()
{
    QString item = adder();
    if(!item.isEmpty())
        this->list->addItem(item);
}

void StringListSelector::bt_remove_clicked()
{
    qDeleteAll(list->selectedItems());
}

