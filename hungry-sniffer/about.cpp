#include "about.h"

#include <QCoreApplication>
#include <QVBoxLayout>
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
