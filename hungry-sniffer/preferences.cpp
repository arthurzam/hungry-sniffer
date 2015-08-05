#include "preferences.h"
#include "sniff_window.h"

#include <QDialogButtonBox>
#include <QHeaderView>
#include <QLineEdit>
#include <QSettings>
#include <QSplitter>
#include <QStackedWidget>
#include <QTreeWidgetItem>
#include <QVBoxLayout>

std::vector<Preferences::reloadFunc_t> Preferences::reloadFunctions;

static QTreeWidgetItem* getItem(const HungrySniffer_Core::Preference& pref, QStackedWidget* stack, std::vector<hungry_sniffer::PreferencePanel*>& panels)
{
    QTreeWidgetItem* item = new QTreeWidgetItem(QStringList(QString::fromStdString(pref.name)));
    if(pref.func)
    {
        hungry_sniffer::PreferencePanel* panel = pref.func(*SniffWindow::core, *Preferences::settings);
        QWidget* widget = panel->get();
        stack->addWidget(widget);
        item->setData(0, Qt::UserRole, QVariant::fromValue<QWidget*>(widget));
        panels.push_back(panel);
    }
    else
    {
        Qt::ItemFlags flags = item->flags();
        flags &= ~Qt::ItemIsSelectable;
        item->setFlags(flags);
    }
    for(const auto& i : pref.subPreferences)
        item->addChild(getItem(i, stack, panels));
    return item;
}

static QWidget* extractData(QTreeWidgetItem* item)
{
    if(item)
    {
        QVariant var = item->data(0, Qt::UserRole);
        if(!var.isNull())
            return var.value<QWidget*>();
    }
    return nullptr;
}

Preferences::Preferences(QWidget* parent) :
    QDialog(parent)
{
    this->resize(400, 300);
    QVBoxLayout* verticalLayout_2 = new QVBoxLayout(this);
    splitter = new QSplitter(this);
    splitter->setOrientation(Qt::Horizontal);
    splitter->setSizes(QList<int>({175, 400 - 175}));

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

    QDialogButtonBox* buttonBox = new QDialogButtonBox(this);
    buttonBox->setOrientation(Qt::Horizontal);
    buttonBox->setStandardButtons(QDialogButtonBox::Cancel | QDialogButtonBox::Ok);
    verticalLayout_2->addWidget(buttonBox);

    stackedWidget->addWidget(new QWidget());
    for(const auto& i : SniffWindow::core->preferences)
    {
        tree_select->addTopLevelItem(getItem(i, stackedWidget, this->panels));
    }
    tree_select->expandAll();

    connect(buttonBox, SIGNAL(accepted()), this, SLOT(accept()));
    connect(buttonBox, SIGNAL(rejected()), this, SLOT(reject()));
    connect(tb_search, SIGNAL(textChanged(QString)), this, SLOT(on_tb_search_textEdited(QString)));
    connect(tree_select, SIGNAL(currentItemChanged(QTreeWidgetItem*, QTreeWidgetItem*)), this, SLOT(on_tree_select_currentItemChanged(QTreeWidgetItem*, QTreeWidgetItem*)));
}

Preferences::~Preferences()
{
}

void Preferences::accept()
{
    for(hungry_sniffer::PreferencePanel* panel : this->panels)
    {
        panel->save(*settings);
    }
    settings->sync();
    for(reloadFunc_t func : reloadFunctions)
        func(*settings);
    QDialog::accept();
}

void Preferences::on_tree_select_currentItemChanged(QTreeWidgetItem* current, QTreeWidgetItem* previous)
{
    if(current == previous) return;
    QWidget* item = extractData(current);
    if(item)
        stackedWidget->setCurrentWidget(item);
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

void Preferences::on_tb_search_textEdited(const QString& arg1)
{
    int end = tree_select->topLevelItemCount();
    for(int i = 0; i < end; i++)
    {
        filterEntries(tree_select->topLevelItem(i), arg1);
    }
}
