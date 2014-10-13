#ifndef DEVICECHOOSE_H
#define DEVICECHOOSE_H

#include <QDialog>
#include <QAbstractButton>
#include <vector>
#include <string>

namespace Ui {
class DeviceChoose;
}

class DeviceChoose : public QDialog
{
    Q_OBJECT

public:
    explicit DeviceChoose(QWidget *parent = 0);
    ~DeviceChoose();

    std::vector<std::string> results;

private slots:
    void on_buttonBox_clicked(QAbstractButton *button);

private:
    Ui::DeviceChoose *ui;

    void refreshDevices();
};

#endif // DEVICECHOOSE_H
