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

#include "devicechoose.h"
#include "preferences.h"
#include "widgets/interface_selector.h"

#include <QPushButton>
#include <QLabel>
#include <QBoxLayout>
#include <QDialogButtonBox>
#include <QLineEdit>
#include <QSpinBox>
#include <QSettings>

#include <stdint.h>
#if defined(Q_OS_WIN)
    #include <ws2tcpip.h>
#elif defined(Q_OS_UNIX)
    #include <arpa/inet.h>
    #include <netdb.h>
#endif

DeviceChoose::DeviceChoose(QWidget* parent) :
    QDialog(parent)
{
    this->resize(400, 300);
    this->setWindowTitle(QStringLiteral("Interface Chooser"));
    QVBoxLayout* vbox = new QVBoxLayout(this);

    QStringList hidden = Preferences::settings->value(QStringLiteral("HiddenInf")).toStringList();
    vbox->addWidget(tableView = new InterfaceSelector(hidden));

    QHBoxLayout* hbox_filter = new QHBoxLayout();
    hbox_filter->addWidget(new QLabel(QStringLiteral("Capture Filter"), this));
    tb_filter = new QLineEdit(this);
    tb_filter->setToolTip(QStringLiteral("Capture Filter in Pcap format"));
    hbox_filter->addWidget(tb_filter);
    vbox->addLayout(hbox_filter);

    QHBoxLayout* hbox_num = new QHBoxLayout();
    hbox_num->addWidget(new QLabel(QStringLiteral("Max Capture Number"), this));
    tb_number = new QSpinBox(this);
    tb_number->setValue(0);
    tb_number->setRange(0, INT_MAX);
    tb_number->setToolTip(QStringLiteral("Maximum number of packets to\ncapture from those interfaces"));
    hbox_num->addWidget(tb_number);
    vbox->addLayout(hbox_num);

    QDialogButtonBox* buttonBox = new QDialogButtonBox(this);
    buttonBox->setStandardButtons(QDialogButtonBox::Cancel | QDialogButtonBox::Ok);
    QPushButton* btRefresh = new QPushButton(QStringLiteral("&Refresh"), buttonBox);
    connect(btRefresh, SIGNAL(clicked()), tableView, SLOT(refresh()));
    buttonBox->addButton(btRefresh, QDialogButtonBox::ActionRole);
    connect(buttonBox, SIGNAL(accepted()), this, SLOT(on_buttonBox_accepted()));
    connect(buttonBox, SIGNAL(rejected()), this, SLOT(close()));
    vbox->addWidget(buttonBox);
}

QString DeviceChoose::getCaptureFilter() const
{
    return tb_filter->text();
}

int DeviceChoose::getMaxCaptureNumber() const
{
    int val = tb_number->value();
    if(val == 0)
        return -1;
    return val;
}

void DeviceChoose::on_buttonBox_accepted()
{
    this->results = tableView->getSelected();
    this->close();
}
