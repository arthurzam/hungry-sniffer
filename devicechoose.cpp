#include "devicechoose.h"
#include "ui_devicechoose.h"

#include <QMessageBox>
#include <QPushButton>
#include <QCheckBox>
#include <QLabel>

#include <dirent.h>
#include <cstdio>

DeviceChoose::DeviceChoose(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::DeviceChoose)
{
    ui->setupUi(this);

    ui->buttonBox->addButton(new QPushButton(tr("&Refresh")), QDialogButtonBox::AcceptRole);

    this->refreshDevices();
    this->resize(0, 0);
}

void DeviceChoose::refreshDevices()
{
    DIR* dir = opendir("/sys/class/net/");
    if(!dir)
    {
        QMessageBox::warning(this, "Error", "Error getting the interfaces\n""Are you root?");
        return;
        this->close();
    }

    // clear the table
    while(ui->gridLayout->count() > 0)
    {
        QWidget* widget = ui->gridLayout->itemAt(0)->widget();
        ui->gridLayout->removeWidget(widget);
        delete widget;
    }

    struct dirent *ent;
    char MAC[32];
    char path[64];
    FILE* file;
    int row = 0;
    while ((ent = readdir (dir)))
    {
        std::sprintf(path, "/sys/class/net/%s/address", ent->d_name);
        if((file = std::fopen(path, "r")))
        {
            MAC[std::fread(MAC, 1, 32, file)] = '\0';
            ui->gridLayout->addWidget(new QCheckBox(this), row, 0);
            ui->gridLayout->addWidget(new QLabel(QString(ent->d_name), this), row, 1);
            ui->gridLayout->addWidget(new QLabel(QString(MAC), this), row, 2);
            std::fclose(file);
            ++row;
        }
    }
    closedir(dir);
}

DeviceChoose::~DeviceChoose()
{
    delete ui;
}

void DeviceChoose::on_buttonBox_clicked(QAbstractButton *button)
{
    QPushButton& bt = *((QPushButton*)button);
    QString st = bt.text();
    if(st == "&Refresh")
    {
        this->refreshDevices();
    }
    else if(st == "&OK")
    {
        this->results.clear();
        for(int row = 0; row < ui->gridLayout->rowCount(); ++row)
        {
            QCheckBox* cb = (QCheckBox*)ui->gridLayout->itemAtPosition(row, 0)->widget();
            if(cb->isChecked())
            {
                QLabel* lb = (QLabel*)ui->gridLayout->itemAtPosition(row, 1)->widget();
                this->results.push_back(lb->text().toStdString());
                cb->setChecked(false);
            }
        }
        this->close();
    }
    else if(st == "&Cancel")
    {
        this->close();
    }
}
