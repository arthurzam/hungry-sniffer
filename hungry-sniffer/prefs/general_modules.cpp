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

#include "general_modules.h"
#include "ui_general_modules.h"
#include "widgets/string_list_selector.h"
#include <QFileDialog>
#include <QSettings>

QString getDir()
{
    return QFileDialog::getExistingDirectory(nullptr, QStringLiteral("Select default open folder"));
}

GeneralModules::GeneralModules(QWidget* parent) :
    QWidget(parent),
    ui(new Ui::GeneralModules)
{
    ui->setupUi(this);

    QVBoxLayout* plugins = new QVBoxLayout(ui->groupBox);
    this->list_plugins = new StringListSelector(&getDir, this);
    plugins->addWidget(this->list_plugins);

    QVBoxLayout* python = new QVBoxLayout(ui->groupBox_2);
    this->list_python = new StringListSelector(&getDir, this);
    python->addWidget(this->list_python);
}

GeneralModules::~GeneralModules()
{
    delete ui;
}

void GeneralModules::save(QSettings& settings)
{
    settings.beginGroup(QStringLiteral("General"));
    settings.beginGroup(("Modules"));
    settings.setValue(QStringLiteral("plugins_dir"), this->list_plugins->getItems());
    settings.setValue(QStringLiteral("python_dir"), this->list_python->getItems());
    settings.endGroup();
    settings.endGroup();
}

hungry_sniffer::PreferencePanel* GeneralModules::init(const HungrySniffer_Core&, QSettings& settings)
{
    GeneralModules* res = new GeneralModules();

    settings.beginGroup(QStringLiteral("General"));
    settings.beginGroup(QStringLiteral("Modules"));
    res->list_plugins->addItems(settings.value(QStringLiteral("plugins_dir"), QStringList()).toStringList());
    res->list_python->addItems(settings.value(QStringLiteral("python_dir"), QStringList()).toStringList());
    settings.endGroup();
    settings.endGroup();

    return res;
}
