#include "general_ui.h"
#include "ui_general_ui.h"
#include "../sniff_window.h"

#include <QSettings>
#include <QFileDialog>

GeneralUI::GeneralUI(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::GeneralUI)
{
    ui->setupUi(this);
}

GeneralUI::~GeneralUI()
{
    delete ui;
}

void GeneralUI::save(QSettings& settings)
{
    settings.beginGroup(QStringLiteral("General"));
    settings.beginGroup(("UI"));
    SniffWindow::window->model.showColors = ui->cb_colored->isChecked();
    settings.setValue(QStringLiteral("colored_packets"), ui->cb_colored->isChecked());
    settings.setValue(QStringLiteral("splitter_sizes"), ui->cb_splitter_sizes->isChecked());
    SniffWindow::window->default_open_location = ui->tb_default_dir->text();
    settings.setValue(QStringLiteral("default_dir"), ui->tb_default_dir->text());
    settings.endGroup();
    settings.endGroup();
}

hungry_sniffer::PreferencePanel* GeneralUI::init(const HungrySniffer_Core& core, QSettings& settings)
{
    GeneralUI* res = new GeneralUI();

    settings.beginGroup(QStringLiteral("General"));
    settings.beginGroup(QStringLiteral("UI"));
    res->ui->cb_colored->setChecked(settings.value(QStringLiteral("colored_packets"), true).toBool());
    res->ui->cb_splitter_sizes->setChecked(settings.value(QStringLiteral("splitter_sizes"), false).toBool());
    res->ui->tb_default_dir->setText(settings.value(QStringLiteral("default_dir"), QStringLiteral()).toString());
    settings.endGroup();
    settings.endGroup();

    return res;
}

void GeneralUI::on_bt_default_dir_clicked()
{
    QString dir = QFileDialog::getExistingDirectory(this, QStringLiteral("Select default open folder"), ui->tb_default_dir->text());
    if(!dir.isEmpty())
        ui->tb_default_dir->setText(dir);
}
