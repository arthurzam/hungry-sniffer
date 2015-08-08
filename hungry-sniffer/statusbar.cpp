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

#include "statusbar.h"
#include "sniff_window.h"

#include <QGridLayout>

StatusBar::StatusBar(QWidget* parent) :
    QStatusBar(parent),
    lb_info(this),
    lb_liveSniffing(this)
{
    this->setStyleSheet(QStringLiteral("QStatusBar::item{border: none;}"));

    QWidget* widget = new QWidget();
    QGridLayout* layout = new QGridLayout(widget);
    layout->addWidget(&lb_liveSniffing, 0, 0, 1, 1, Qt::AlignVCenter | Qt::AlignLeft);
    layout->addWidget(&lb_info, 0, 1, 1, 1, Qt::AlignVCenter | Qt::AlignRight);
    this->addWidget(widget, 1);

    updateText();
}

void StatusBar::updateText(int selectedRow)
{
    if(selectedRow != -1)
        this->selectedRow = selectedRow;
    int all = SniffWindow::window->model.local.size();
    int displayed = SniffWindow::window->model.shownPerRow.size();
    this->lb_info.setText(QStringLiteral("Packets:%1 * Displayed:%2 * Selected:%3").arg(all).arg(displayed).arg(this->selectedRow));
}

void StatusBar::setLiveSniffing(bool state)
{
    this->lb_liveSniffing.setText(state ? QStringLiteral("Live Sniffing") : QStringLiteral(""));
}

