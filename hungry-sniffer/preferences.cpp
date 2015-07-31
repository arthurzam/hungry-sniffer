#include "preferences.h"
#include "ui_preferences.h"
#include "sniff_window.h"

#include <QSettings>
#include <QTreeWidgetItem>

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
        // TODO: find a way to set this as unselectable
    }
    for(const auto& i : pref.subPreferences)
        item->addChild(getItem(i, stack, panels));
    return item;
}

Preferences::Preferences(QWidget* parent) :
    QDialog(parent),
    ui(new Ui::Preferences)
{
    ui->setupUi(this);
    ui->stackedWidget->addWidget(new QWidget());
    for(const auto& i : SniffWindow::core->preferences)
    {
        ui->tree_select->addTopLevelItem(getItem(i, ui->stackedWidget, this->panels));
    }
}

Preferences::~Preferences()
{
    delete ui;
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
    QVariant var = current->data(0, Qt::UserRole);
    if(var.isNull()) return;
    QWidget* item = var.value<QWidget*>();
    if(item)
        ui->stackedWidget->setCurrentWidget(item);
}
