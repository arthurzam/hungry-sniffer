#include "string_list_selector.h"

#include <QHBoxLayout>
#include <QVBoxLayout>
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

