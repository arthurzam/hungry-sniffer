#ifndef DEVICECHOOSE_H
#define DEVICECHOOSE_H

#include <QDialog>

namespace Ui {
class DeviceChoose;
}

class DeviceChoose : public QDialog
{
    Q_OBJECT

public:
    explicit DeviceChoose(QWidget *parent = 0);
    ~DeviceChoose();

    QStringList results;

private slots:

    void on_buttonBox_accepted();

    void on_buttonBox_rejected();

    void refreshDevices();
private:
    Ui::DeviceChoose *ui;
};

#endif // DEVICECHOOSE_H
