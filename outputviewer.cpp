#include "outputviewer.h"
#include "ui_outputviewer.h"
#include <sstream>

OutputViewer::OutputViewer(const std::stringstream& stream, const std::string& name, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::OutputViewer)
{
    ui->setupUi(this);
    ui->tb->appendHtml(QString::fromStdString(stream.str()).replace("\n", "<br />"));
    this->setWindowTitle(QString::fromStdString(name));
}

OutputViewer::~OutputViewer()
{
    delete ui;
}
