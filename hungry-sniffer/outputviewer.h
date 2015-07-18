#ifndef OUTPUTVIEWER_H
#define OUTPUTVIEWER_H

#include <QDialog>

class QPlainTextEdit;

/**
 * @brief Output Dialog
 */
class OutputViewer : public QDialog
{
    public:
        /**
         * @brief OutputViewer constructor
         *
         * @param stream the source string stream for the text output
         * @param name the name for the window
         */
        explicit OutputViewer(const std::stringstream& stream, const std::string& name, QWidget *parent = 0);

    private:
        QPlainTextEdit* tb;
};

#endif // OUTPUTVIEWER_H
