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
#include "../sniff_window.h"

#include <QBoxLayout>
#include <QCheckBox>
#include <QFileDialog>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QSettings>
#include <QSpacerItem>
#include <QSpinBox>

GeneralUI::GeneralUI() :
    QWidget(nullptr)
{
    this->resize(400, 300);
    QVBoxLayout* vbox = new QVBoxLayout(this);

    cb_splitter_sizes = new QCheckBox(this);
    cb_splitter_sizes->setText(QStringLiteral("Remember Splitter Sizes"));
    vbox->addWidget(cb_splitter_sizes);

    cb_colored = new QCheckBox(this);
    cb_colored->setText(QStringLiteral("Enable Colored Packets"));
    vbox->addWidget(cb_colored);

    QHBoxLayout* layout_open = new QHBoxLayout();
    layout_open->addWidget(tb_default_dir = new QLineEdit(this));
    QPushButton* bt_default_dir = new QPushButton(this);
    connect(bt_default_dir, SIGNAL(clicked()), this, SLOT(on_bt_default_dir_clicked()));
    bt_default_dir->setIcon(QIcon(QStringLiteral(":/icons/open.png")));
    layout_open->addWidget(bt_default_dir);
    vbox->addLayout(layout_open);

    QHBoxLayout* layout_recents = new QHBoxLayout();
    layout_recents->addWidget(new QLabel(QStringLiteral("Max Number of Recents"), this));
    layout_recents->addWidget(tb_recents_num = new QSpinBox(this));

    vbox->addLayout(layout_recents);
    vbox->addItem(new QSpacerItem(20, 40, QSizePolicy::Minimum, QSizePolicy::Expanding));
}

GeneralUI::~GeneralUI()
{
}

void GeneralUI::save(QSettings& settings)
{
    settings.beginGroup(QStringLiteral("General"));
    settings.beginGroup(("UI"));
    SniffWindow::window->model.showColors = cb_colored->isChecked();
    settings.setValue(QStringLiteral("colored_packets"), cb_colored->isChecked());
    settings.setValue(QStringLiteral("splitter_sizes"), cb_splitter_sizes->isChecked());
    SniffWindow::window->default_open_location = tb_default_dir->text();
    settings.setValue(QStringLiteral("default_dir"), tb_default_dir->text());
    SniffWindow::window->max_recent_files = tb_recents_num->value();
    SniffWindow::window->updateRecentsMenu();
    settings.setValue(QStringLiteral("max_recent_files"), tb_recents_num->value());
    settings.endGroup();
    settings.endGroup();
}

hungry_sniffer::Preference::Panel* GeneralUI::init(QSettings& settings)
{
    GeneralUI* res = new GeneralUI();

    settings.beginGroup(QStringLiteral("General"));
    settings.beginGroup(QStringLiteral("UI"));
    res->cb_colored->setChecked(settings.value(QStringLiteral("colored_packets"), true).toBool());
    res->cb_splitter_sizes->setChecked(settings.value(QStringLiteral("splitter_sizes"), false).toBool());
    res->tb_default_dir->setText(settings.value(QStringLiteral("default_dir")).toString());
    res->tb_recents_num->setValue(SniffWindow::window->max_recent_files);
    settings.endGroup();
    settings.endGroup();

    return res;
}

void GeneralUI::on_bt_default_dir_clicked()
{
    QString dir = QFileDialog::getExistingDirectory(this, QStringLiteral("Select default open folder"), tb_default_dir->text());
    if(!dir.isEmpty())
        tb_default_dir->setText(dir);
}
