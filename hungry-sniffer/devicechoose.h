#ifndef DEVICECHOOSE_H
#define DEVICECHOOSE_H

#include <QDialog>
#include <QAbstractTableModel>
#include <pcap.h>

class QTableView;
class QSortFilterProxyModel;
class QLineEdit;
class QSpinBox;

class DeviceModel : public QAbstractTableModel
{
        Q_OBJECT
    private:
        struct Device {
            QString name;
            QString description;
            QString addr1;
            QString allAddr;

            Device(pcap_if_t* p);
            Device(Device&& other);
        };
        std::vector<Device> list;

    public:
        explicit DeviceModel(QObject* parent = nullptr) : QAbstractTableModel(parent)
        {
            this->refresh();
        }

        int rowCount(const QModelIndex & = QModelIndex()) const
        {
            return list.size();
        }

        int columnCount(const QModelIndex & = QModelIndex()) const
        {
            return 3;
        }

        QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const;
        QVariant headerData(int section, Qt::Orientation orientation, int role) const;

    public slots:
        void refresh();
};

/**
 * @brief Choosing Device for Sniffing Dialog
 */
class DeviceChoose : public QDialog
{
        Q_OBJECT
    private:
        QTableView* tableView;
        QStringList results;
        QSortFilterProxyModel* m_sortFilterProxy;
        QLineEdit* tb_filter;
        QSpinBox* tb_number;

        DeviceModel* model;
    public:
        explicit DeviceChoose(QWidget* parent = 0);
        ~DeviceChoose() {}

        QStringList::const_iterator end() const
        {
            return results.cend();
        }

        QStringList::const_iterator begin() const
        {
            return results.cbegin();
        }

        QString getCaptureFilter() const;
        int getMaxCaptureNumber() const;

    private slots:

        /**
         * @brief on_buttonBox_accepted in case OK was clicked, save the chosen in results
         */
        void on_buttonBox_accepted();
};

#endif // DEVICECHOOSE_H
