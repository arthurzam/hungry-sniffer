/*
    Copyright (c) 2015 Zamarin Arthur

    Permission is hereby granted, free of charge, to any person obtaining
    a copy of this software and associated documentation files (the "Software"),
    to deal in the Software without restriction, including without limitation
    the rights to use, copy, modify, merge, publish, distribute, sublicense,
    and/or sell copies of the Software, and to permit persons to whom the Software
    is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
    EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
    OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
    IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
    CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
    TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
    OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "about_plugins.h"

#include <QAbstractTableModel>
#include <QFileInfo>
#include <QHeaderView>
#include <QLibrary>
#include <QTableView>
#include <QVBoxLayout>

AboutPlugins* AboutPlugins::window = nullptr;

class PluginsModel : public QAbstractTableModel
{
    public:
        struct Plugin {
            QString filename;
            QString description;
            QString website;
            QString copyright;

            Plugin(QLibrary& lib);
        };
        std::vector<Plugin> list;

        explicit PluginsModel(QObject* parent = nullptr) : QAbstractTableModel(parent)
        {
        }

        int rowCount(const QModelIndex & = QModelIndex()) const
        {
            return list.size();
        }

        int columnCount(const QModelIndex & = QModelIndex()) const
        {
            return 4;
        }

        QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const;

        QVariant headerData(int section, Qt::Orientation orientation, int role) const;
        void addPlugin(QLibrary& lib);
};

AboutPlugins::AboutPlugins() :
    QDialog(nullptr)
{
    this->setWindowTitle(QStringLiteral("About Plugins"));
    QVBoxLayout* box = new QVBoxLayout(this);
    QTableView* table = new QTableView(this);
    table->verticalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    table->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->setModel(this->model = new PluginsModel(this));
    box->addWidget(table);
}

void AboutPlugins::init()
{
    window = new AboutPlugins();
}

void PluginsModel::addPlugin(QLibrary& lib)
{
    int row = this->list.size();
    beginInsertRows(QModelIndex(), row, row);
    list.push_back(lib);
    endInsertRows();
}

void AboutPlugins::addPlugin(QLibrary& lib)
{
    model->addPlugin(lib);
}

PluginsModel::Plugin::Plugin(QLibrary& lib)
{
    typedef const char* (*info_string_t)();
    info_string_t func = (info_string_t)lib.resolve("PLUGIN_DESCRIPTION");
    if(func)
        this->description.append(func());
    func = (info_string_t)lib.resolve("PLUGIN_WEBSITE");
    if(func)
        this->website.append(func());
    func = (info_string_t)lib.resolve("PLUGIN_COPYRIGHT");
    if(func)
        this->copyright.append(func());
    this->filename = lib.fileName();
}

QVariant PluginsModel::data(const QModelIndex& index, int role) const
{
    const Plugin& p = list[index.row()];
    switch(role)
    {
        case Qt::ItemDataRole::ToolTipRole:
            switch(index.column())
            {
                case 0:
                    return p.filename;
            }
        case Qt::ItemDataRole::DisplayRole:
            switch(index.column())
            {
                case 0:
                    return QFileInfo(p.filename).fileName();
                case 1:
                    return p.description;
                case 2:
                    return p.website;
                case 3:
                    return p.copyright;
            }
            break;
    }
    return QVariant();
}

static const QString headers[] = {QStringLiteral("Name"), QStringLiteral("Description"),
                                  QStringLiteral("Website"), QStringLiteral("Copyright")};

QVariant PluginsModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if ((role == Qt::DisplayRole) & (orientation == Qt::Horizontal))
    {
        return headers[section];
    }

    return QVariant();
}
