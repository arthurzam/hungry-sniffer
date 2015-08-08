#include "general_modules.h"
#include "ui_general_modules.h"
#include "widgets/string_list_selector.h"
#include <QFileDialog>
#include <QSettings>

QString getDir()
{
    return QFileDialog::getExistingDirectory(nullptr, QStringLiteral("Select default open folder"));
}

GeneralModules::GeneralModules(QWidget* parent) :
    QWidget(parent),
    ui(new Ui::GeneralModules)
{
    ui->setupUi(this);

    QVBoxLayout* plugins = new QVBoxLayout(ui->groupBox);
    this->list_plugins = new StringListSelector(&getDir, this);
    plugins->addWidget(this->list_plugins);

    QVBoxLayout* python = new QVBoxLayout(ui->groupBox_2);
    this->list_python = new StringListSelector(&getDir, this);
    python->addWidget(this->list_python);
}

GeneralModules::~GeneralModules()
{
    delete ui;
}

void GeneralModules::save(QSettings& settings)
{
    settings.beginGroup(QStringLiteral("General"));
    settings.beginGroup(("Modules"));
    settings.setValue(QStringLiteral("plugins_dir"), this->list_plugins->getItems());
    settings.setValue(QStringLiteral("python_dir"), this->list_python->getItems());
    settings.endGroup();
    settings.endGroup();
}

hungry_sniffer::PreferencePanel* GeneralModules::init(const HungrySniffer_Core&, QSettings& settings)
{
    GeneralModules* res = new GeneralModules();

    settings.beginGroup(QStringLiteral("General"));
    settings.beginGroup(QStringLiteral("Modules"));
    res->list_plugins->addItems(settings.value(QStringLiteral("plugins_dir"), QStringList()).toStringList());
    res->list_python->addItems(settings.value(QStringLiteral("python_dir"), QStringList()).toStringList());
    settings.endGroup();
    settings.endGroup();

    return res;
}
