#ifndef DEVICECHOOSE_H
#define DEVICECHOOSE_H

#include <QDialog>

namespace Ui {
    class DeviceChoose;
}

/**
 * @brief Choosing Device for Sniffing Dialog
 */
class DeviceChoose : public QDialog
{
        Q_OBJECT
    private:
        Ui::DeviceChoose* ui;
        QStringList results;
    public:
        explicit DeviceChoose(QWidget* parent = 0);
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

        /**
         * @brief on_buttonBox_accepted in case OK was clicked, save the chosen in results
         */
        void on_buttonBox_accepted();

        /**
         * @brief refreshDevices update the devices in the table
         */
        void refreshDevices();
};

#endif // DEVICECHOOSE_H
