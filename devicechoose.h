#ifndef DEVICECHOOSE_H
#define DEVICECHOOSE_H

#include <QDialog>

namespace Ui {
class DeviceChoose;
}

class DeviceChoose : public QDialog
{
    Q_OBJECT
private:
    QStringList results;
public:
    explicit DeviceChoose(QWidget *parent = 0);
    ~DeviceChoose();

    QStringList::const_iterator end() const
    {
        return results.cend();
    }

    QStringList::const_iterator begin() const
    {
        return results.cbegin();
    }

private slots:

    void on_buttonBox_accepted();

    void refreshDevices();
private:
    Ui::DeviceChoose *ui;
};

#endif // DEVICECHOOSE_H
