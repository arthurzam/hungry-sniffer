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

#include "about.h"

#include <QCoreApplication>
#include <QBoxLayout>
#include <QTextBrowser>
#include <QLabel>
#include <QFont>

About::About(QWidget *parent) :
    QDialog(parent)
{
    this->resize(300, 200);
    this->setWindowTitle(QStringLiteral("About"));
    QVBoxLayout* verticalLayout = new QVBoxLayout(this);

    QLabel* title = new QLabel(QCoreApplication::applicationName());
    QFont font;
    font.setBold(true);
    font.setPointSize(font.pointSize() + 4);
    title->setFont(font);
    verticalLayout->addWidget(title);

    verticalLayout->addWidget(new QLabel(QStringLiteral("Version %1").arg(QCoreApplication::applicationVersion())));

    QTextBrowser* text = new QTextBrowser(this);
    text->setHtml(QStringLiteral("<p><a href=\"https://github.com/arthurzam/hungry-sniffer\">https://github.com/arthurzam/hungry-sniffer</a></p>"
                                 "<p>This program was created by Arthur Zamarin, <a href=\"mailto:arthurzam@gmail.com\">arthurzam@gmail.com</a></p>"
                                 "<p>This program is licensed under the MIT license</p>"));
    text->setOpenExternalLinks(true);
    verticalLayout->addWidget(text);
}
