#ifndef OUTPUTVIEWER_H
#define OUTPUTVIEWER_H

#include <QDialog>

namespace Ui {
class OutputViewer;
}

class OutputViewer : public QDialog
{
        Q_OBJECT

    public:
        explicit OutputViewer(const std::stringstream& stream, const std::string& name, QWidget *parent = 0);
        ~OutputViewer();

    private:
        Ui::OutputViewer *ui;
};

#endif // OUTPUTVIEWER_H
