#include "outputviewer.h"
#include <QVBoxLayout>
#include <QPlainTextEdit>
#include <sstream>

OutputViewer::OutputViewer(const std::stringstream& stream, const std::string& name, QWidget *parent) :
    QDialog(parent)
{
    this->resize(400, 300);
    QVBoxLayout* verticalLayout = new QVBoxLayout(this);
    tb = new QPlainTextEdit(this);
    tb->setReadOnly(true);
    verticalLayout->addWidget(tb);

    tb->appendHtml(QString::fromStdString(stream.str()).replace("\n", "<br />"));
    this->setWindowTitle(QString::fromStdString(name));
}
