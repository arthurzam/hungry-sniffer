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
    SniffWindow::window->max_recent_files = ui->tb_recents_num->value();
    SniffWindow::window->updateRecentsMenu();
    settings.setValue(QStringLiteral("max_recent_files"), ui->tb_recents_num->value());
    settings.endGroup();
    settings.endGroup();
}

hungry_sniffer::Preference::Panel* GeneralUI::init(const HungrySniffer_Core&, QSettings& settings)
{
    GeneralUI* res = new GeneralUI();

    settings.beginGroup(QStringLiteral("General"));
    settings.beginGroup(QStringLiteral("UI"));
    res->ui->cb_colored->setChecked(settings.value(QStringLiteral("colored_packets"), true).toBool());
    res->ui->cb_splitter_sizes->setChecked(settings.value(QStringLiteral("splitter_sizes"), false).toBool());
    res->ui->tb_default_dir->setText(settings.value(QStringLiteral("default_dir"), QStringLiteral()).toString());
    res->ui->tb_recents_num->setValue(SniffWindow::window->max_recent_files);
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
