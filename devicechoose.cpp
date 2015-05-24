#include "devicechoose.h"
#include "ui_devicechoose.h"

#include <QMessageBox>
#include <QPushButton>
#include <QCheckBox>
#include <QLabel>

#include <dirent.h>
#include <cstdio>

#include <QDir>

DeviceChoose::DeviceChoose(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::DeviceChoose)
{
    ui->setupUi(this);

    QPushButton* btRefresh = new QPushButton(QLatin1String("&Refresh"), ui->buttonBox);
    connect(btRefresh, SIGNAL(clicked()), this, SLOT(refreshDevices()));
    ui->buttonBox->addButton(btRefresh, QDialogButtonBox::ActionRole);

    this->refreshDevices();

    this->setFixedSize(0, 0);
}

void DeviceChoose::refreshDevices()
{
    // clear the table
    while(ui->gridLayout->count() > 0)
    {
        QWidget* widget = ui->gridLayout->itemAt(0)->widget();
        ui->gridLayout->removeWidget(widget);
        delete widget;
    }

    QDir dir(QLatin1String("/sys/class/net/"));
    QStringList allFiles = dir.entryList(QDir::NoDotAndDotDot | QDir::System | QDir::Hidden  | QDir::AllDirs | QDir::Files);
    QListIterator<QString> iter(allFiles);
    for(int row = 0; iter.hasNext(); ++row)
    {
        QString name = iter.next();
        QFile file(QStringLiteral("/sys/class/net/%1/address").arg(name));
        if(!file.open(QIODevice::ReadOnly))
        {
            QMessageBox::warning(this, QLatin1String("Error"), QLatin1String("Error getting the interfaces\n""Are you root?"));
            this->close();
            return;
        }

        ui->gridLayout->addWidget(new QCheckBox(this), row, 0);
        ui->gridLayout->addWidget(new QLabel(name, this), row, 1);
        ui->gridLayout->addWidget(new QLabel(QString(file.readAll()), this), row, 2);
        file.close();
    }
}

DeviceChoose::~DeviceChoose()
{
    delete ui;
}

void DeviceChoose::on_buttonBox_accepted()
{
    this->results.clear();
    for(int row = 0; row < ui->gridLayout->rowCount(); ++row)
    {
        QCheckBox* cb = (QCheckBox*)ui->gridLayout->itemAtPosition(row, 0)->widget();
        if(cb->isChecked())
        {
            QLabel* lb = (QLabel*)ui->gridLayout->itemAtPosition(row, 1)->widget();
            this->results.append(lb->text());
            cb->setChecked(false);
        }
    }
    this->close();
}
