#ifndef OUTPUTVIEWER_H
#define OUTPUTVIEWER_H

#include <QDialog>

namespace Ui {
    class OutputViewer;
}

/**
 * @brief Output Dialog
 */
class OutputViewer : public QDialog
{
        Q_OBJECT

    public:
        /**
         * @brief OutputViewer constructor
         *
         * @param stream the source string stream for the text output
         * @param name the name for the window
         */
        explicit OutputViewer(const std::stringstream& stream, const std::string& name, QWidget *parent = 0);
        ~OutputViewer();

    private:
        Ui::OutputViewer *ui;
};

#endif // OUTPUTVIEWER_H
