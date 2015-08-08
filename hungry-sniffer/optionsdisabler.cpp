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

#include "optionsdisabler.h"
#include <QLabel>
#include <QPushButton>
#include <QGridLayout>
#include <QVBoxLayout>

OptionsDisabler::OptionsDisabler(QWidget *parent) :
    QDialog(parent)
{
    this->resize(400, 300);
    QVBoxLayout* verticalLayout = new QVBoxLayout(this);
    grid = new QGridLayout();
    verticalLayout->addLayout(grid);

    this->setWindowTitle(QStringLiteral("Options Disabler"));
    this->setFixedSize(0, 0);
}

OptionsDisabler::~OptionsDisabler()
{
//    for(auto& i : this->enabledOptions)
//    {
//        free(const_cast<void*>(i.data));
//    }
}

void OptionsDisabler::refreshOptions()
{
    // clear the table
    while(grid->count() > 0)
    {
        QWidget* widget = grid->itemAt(0)->widget();
        grid->removeWidget(widget);
        delete widget;
    }
    int row = 0;
    for(const auto& i : this->enabledOptions)
    {
        grid->addWidget(new QLabel(QString::fromStdString(i.name), this), row, 0);
        QPushButton* bt = new QPushButton(QStringLiteral("Disable"), this);

        connect(bt, &QPushButton::clicked, [this, row]() {
            auto iter = this->enabledOptions.begin();
            for(int j = 0; j < row; ++j) ++iter;
            hungry_sniffer::Option::optionDisableFunction disable_func = iter->disable_func;
            if(!disable_func)
                qDebug("disable function NULL for %s", iter->name.c_str());
            else if(disable_func(iter->data))
            {
                this->enabledOptions.erase(iter);
                this->refreshOptions();
            }
        });

        grid->addWidget(bt, row, 1);

        ++row;
    }
    if(row == 0)
    {
        this->hide();
    }
}
