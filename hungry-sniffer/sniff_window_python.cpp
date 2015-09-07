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

#ifdef PYTHON_CMD
#ifdef WIN32
    #include <cmath>
#endif

#undef _DEBUG
#include "Python.h"
#include "structmember.h"

#include "sniff_window.h"
#include "ui_sniff_window.h"
#include "widgets/history_line_edit.h"
#include "EthernetPacket.h"
#include "preferences.h"

#include <QPlainTextEdit>
#include <QSettings>
#include <hs_core.h>

#if PY_MAJOR_VERSION < 3
    typedef void initModuleReturn;
    #define PyUnicode_AsUTF8 PyString_AsString
    #define GetPyString PyString_FromString
#else
    typedef PyObject* initModuleReturn;
    #define GetPyString PyUnicode_FromString
#endif

#define HS_PYDICT_ADD_OBJECT(dict, k, v) PyDict_SetItem(dict, GetPyString(k), v)
#define HS_PYDICT_ADD_NUM(dict, k, num) HS_PYDICT_ADD_OBJECT(dict, k, PyLong_FromLong(num))
#define HS_PYDICT_ADD_STRING(dict, k, v) HS_PYDICT_ADD_OBJECT(dict, k, GetPyString(v.c_str()))
#define HS_PYDICT_ADD_STRINGS(dict, k, v) HS_PYDICT_ADD_STRING(dict, k.c_str(), v)

static const char* getPythonPath()
{
#ifdef PYTHON_DIR
    return PYTHON_DIR;
#elif defined(Q_OS_WIN)
    return ".";
#elif defined(Q_OS_UNIX)
    return "/usr/share/hungry-sniffer";
#else
    return ".";
#endif
}

#ifdef Q_OS_WIN
    int gettimeofday(struct timeval* tv, struct timezone*);
#endif

namespace hs {

    static PyObject* getPacket(unsigned pos)
    {
        if(pos >= SniffWindow::window->model.local.size())
            return Py_None;
        struct DataStructure::localPacket& pack = SniffWindow::window->model.local[pos];

        PyObject* d = PyDict_New();
        HS_PYDICT_ADD_NUM(d, "num", pos);
        HS_PYDICT_ADD_OBJECT(d, "isShown", PyBool_FromLong(pack.isShown));
#if PY_MAJOR_VERSION < 3
        HS_PYDICT_ADD_OBJECT(d, "data", PyString_FromStringAndSize((const char*)pack.rawPacket.data, pack.rawPacket.len));
#else
        HS_PYDICT_ADD_OBJECT(d, "data", PyByteArray_FromStringAndSize((const char*)pack.rawPacket.data, pack.rawPacket.len));
#endif
        HS_PYDICT_ADD_OBJECT(d, "time", PyFloat_FromDouble(pack.rawPacket.time.tv_sec + (double)pack.rawPacket.time.tv_usec * 0.000001));

        int i = 0;
        for(const hungry_sniffer::Packet* packet = pack.decodedPacket; packet != nullptr; packet = packet->getNext())
        {
            i++;
        }
        HS_PYDICT_ADD_NUM(d, "layers", i);

        return d;
    }

    PyObject* getPacketNum(PyObject*, PyObject* args)
    {
        int pos;
        if (!PyArg_ParseTuple(args, "i", &pos))
        {
            return NULL;
        }
        return getPacket(pos);
    }

    PyObject* getNextShown(PyObject*, PyObject* args)
    {
        int pos;
        if (!PyArg_ParseTuple(args, "i", &pos))
        {
            return NULL;
        }

        auto& list = SniffWindow::window->model.local;
        for(unsigned i = pos; i < list.size(); ++i)
        {
            if(list[i].isShown)
                return getPacket(i);
        }
        return Py_None;
    }

    PyObject* getCountAll(PyObject*)
    {
        return PyLong_FromLong((long)SniffWindow::window->model.local.size());
    }

    PyObject* getCountShown(PyObject*)
    {
        return PyLong_FromLong((long)SniffWindow::window->model.shownPerRow.size());
    }

    PyObject* savePacket(PyObject*, PyObject* args)
    {
        int pos;
        int size;
        const char* b;
#if PY_MAJOR_VERSION < 3
        if (!PyArg_ParseTuple(args, "is#", &pos, &b, &size))
        {
            return NULL;
        }
#else
        PyObject* data;
        if (!PyArg_ParseTuple(args, "iY", &pos, &data))
        {
            return NULL;
        }
        size = PyByteArray_Size(data);
        b = PyByteArray_AsString(data);
#endif

        if(pos == -1)
        {
            DataStructure::RawPacketData raw;
            gettimeofday(&raw.time, nullptr);
            raw.setData(b, size);
            SniffWindow::window->toAdd.push(raw);
        }
        else if(pos < (int)SniffWindow::window->model.local.size())
        {
            struct DataStructure::localPacket& pack = SniffWindow::window->model.local[pos];
            DataStructure::RawPacketData& raw = pack.rawPacket;
            free(raw.data);
            raw.setData(b, size);

            delete pack.decodedPacket;
            pack.decodedPacket = new hungry_sniffer::EthernetPacket(raw.data, raw.len, &HungrySniffer_Core::core->base);

            SniffWindow::window->updateTableShown();
        }
        return Py_None;
    }

    PyObject* removePacket(PyObject*, PyObject* args)
    {
        int pos;
        if (!PyArg_ParseTuple(args, "i", &pos))
        {
            return NULL;
        }
        SniffWindow::window->model.remove(pos);
        SniffWindow::window->ui->statusBar->updateText();
        return Py_None;
    }

    static PyMethodDef methods[] =
    {
        { "getPacketNum", (PyCFunction)getPacketNum, METH_VARARGS, NULL },
        { "getNextShown", (PyCFunction)getNextShown, METH_VARARGS, NULL },
        { "getCountAll", (PyCFunction)getCountAll, METH_NOARGS, NULL },
        { "getCountShown", (PyCFunction)getCountShown, METH_NOARGS, NULL },
        { "savePacket", (PyCFunction)savePacket, METH_VARARGS, NULL },
        { "removePacket", (PyCFunction)removePacket, METH_VARARGS, NULL },
        { NULL, NULL, 0, NULL }
    };

#if PY_MAJOR_VERSION >= 3
    static PyModuleDef module =
    {
        PyModuleDef_HEAD_INIT, "_hs_private", NULL, -1, methods, NULL, NULL, NULL, NULL
    };
#endif

    static initModuleReturn PyInit_hs(void)
    {
#if PY_MAJOR_VERSION < 3
        Py_InitModule("_hs_private", methods);
#else
        return PyModule_Create(&module);
#endif
    }

    namespace packet {
        namespace layer {
            struct layer_obj
            {
                PyObject_HEAD
                PyObject* name;
                PyObject* info;
                PyObject* headers;
            };

            static void layer_dealloc(layer_obj* self)
            {
                Py_XDECREF(self->name);
                Py_XDECREF(self->info);
                Py_XDECREF(self->headers);
                Py_TYPE(self)->tp_free((PyObject*)self);
            }

            static PyObject* layer_new(PyTypeObject* type, PyObject*, PyObject*)
            {
                layer_obj* self;

                self = (layer_obj*)type->tp_alloc(type, 0);
                if (self != NULL)
                {
                    self->name = GetPyString("");
                    if (self->name == NULL)
                    {
                        Py_DECREF(self);
                        return NULL;
                    }

                    self->info = GetPyString("");
                    if (self->info == NULL)
                    {
                        Py_DECREF(self);
                        return NULL;
                    }

                    self->headers = PyDict_New();
                    if (self->headers == NULL)
                    {
                        Py_DECREF(self);
                        return NULL;
                    }
                }

                return (PyObject*)self;
            }

            static int layer_init(layer_obj* self, PyObject* args, PyObject*)
            {
                int row;
                int layerNum;

                if (!PyArg_ParseTuple(args, "ii", &row, &layerNum))
                {
                    return -1;
                }

                const hungry_sniffer::Packet* layer = SniffWindow::window->model.local[row].decodedPacket->getNext(layerNum);

                Py_XDECREF(self->name);
                Py_XDECREF(self->info);
                self->name = GetPyString(layer->getProtocol()->getName().c_str());
                self->info = GetPyString(layer->getInfo().c_str());

                Py_XDECREF(self->headers);
                self->headers = PyDict_New();
                for(auto& i : layer->getHeaders())
                    HS_PYDICT_ADD_STRINGS(self->headers, i.key, i.value);

                return 0;
            }

            static PyMemberDef layer_members[] =
            {
                {(char*)"name", T_OBJECT_EX, offsetof(layer_obj, name), READONLY, NULL},
                {(char*)"info", T_OBJECT_EX, offsetof(layer_obj, info), READONLY, NULL},
                {(char*)"headers", T_OBJECT_EX, offsetof(layer_obj, headers), READONLY, NULL},
                {NULL, 0, 0, 0, NULL}
            };

            static PyObject* layer_repr(layer_obj* self)
            {
#if PY_MAJOR_VERSION < 3
                return PyString_FromFormat("[%s - %s]", PyString_AS_STRING(self->name), PyString_AS_STRING(self->info));
#else
                return PyUnicode_FromFormat("[%U - %U]", self->name, self->info);
#endif
            }

            static PyObject* layer_str(layer_obj* self)
            {
#if PY_MAJOR_VERSION < 3
                PyObject* res = PyString_FromFormat("%s\n%s\n", PyString_AS_STRING(self->name), PyString_AS_STRING(self->info));
#else
                PyObject* res = PyUnicode_FromFormat("%U\n%U\n", self->name, self->info);
#endif

                PyObject* key, *value;
                Py_ssize_t pos = 0;
                while (PyDict_Next(self->headers, &pos, &key, &value))
                {
#if PY_MAJOR_VERSION < 3
                    PyString_ConcatAndDel(&res, PyString_FromFormat("%s : %s\n", PyString_AS_STRING(key), PyString_AS_STRING(value)));
#else
                    PyUnicode_AppendAndDel(&res, PyUnicode_FromFormat("%U : %U\n", key, value));
#endif
                }
                return res;
            }

            static Py_ssize_t layer_len(layer_obj* self)
            {
                return PyDict_Size(self->headers);
            }

            static PyObject* layer_itemAt(layer_obj* self, PyObject* key)
            {
                return PyDict_GetItem(self->headers, key);
            }

            static PyMappingMethods layer_map =
            {
                (lenfunc)layer_len,
                (binaryfunc)layer_itemAt,
                0
            };

#ifdef Q_CC_GNU
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wmissing-field-initializers"
#endif
            static PyTypeObject type =
            {
                PyVarObject_HEAD_INIT(NULL, 0)
                "", sizeof(layer_obj), 0,
                (destructor)layer_dealloc,
                0, 0, 0, 0, (reprfunc)layer_repr, 0, 0, &layer_map, 0, 0, (reprfunc)layer_str, 0, 0, 0,
                Py_TPFLAGS_DEFAULT, NULL, 0, 0, 0, 0, 0, 0, /*methods*/0,
                layer_members, 0, 0, 0, 0, 0, 0, (initproc)layer_init, 0, layer_new
            };

#ifdef Q_CC_GNU
    #pragma GCC diagnostic pop
#endif
            static void init(PyObject* hsModule)
            {
                PyType_Ready(&type);
                Py_INCREF(&type);
                PyModule_AddObject(hsModule, "Layer", (PyObject*)&type);
            }
        }

        struct packet_obj
        {
            PyObject_HEAD
            int num;

            PyObject layersArr;
        };
    }

    namespace filter {
        struct filter_obj
        {
            PyObject_HEAD
        };

        static PyObject* filter_get(PyObject*)
        {
            return GetPyString(SniffWindow::window->ui->tb_filter->text().toUtf8().data());
        }

        static PyObject* filter_clear(PyObject*)
        {
            SniffWindow::window->ui->tb_filter->clear();
            SniffWindow::window->on_bt_filter_apply_clicked();
            return Py_None;
        }

        static PyObject* filter_set(PyObject*, PyObject* args)
        {
            char* str = NULL;
            if (!PyArg_ParseTuple(args, "z", &str))
            {
                return NULL;
            }
            SniffWindow::window->ui->tb_filter->setText(QString(str));
            SniffWindow::window->on_bt_filter_apply_clicked();
            return Py_None;
        }

        static PyMethodDef hs_filter_methods[] =
        {
            {"get", (PyCFunction)filter_get, METH_NOARGS | METH_CLASS, NULL},
            {"clear", (PyCFunction)filter_clear, METH_NOARGS | METH_CLASS, NULL},
            {"set", (PyCFunction)filter_set, METH_VARARGS | METH_CLASS, NULL},
            { NULL, NULL, 0, NULL }
        };

#ifdef Q_CC_GNU
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wmissing-field-initializers"
#endif
        static PyTypeObject type =
        {
            PyVarObject_HEAD_INIT(NULL, 0)
            "", sizeof(filter_obj), 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            Py_TPFLAGS_DEFAULT, NULL, 0, 0, 0, 0, 0, 0, hs_filter_methods,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        };
#ifdef Q_CC_GNU
    #pragma GCC diagnostic pop
#endif
        static void init(PyObject* hsModule)
        {
            PyType_Ready(&type);
            Py_INCREF(&type);
            PyModule_AddObject(hsModule, "filter", (PyObject*)&type);
        }
    }
}

namespace ui {
    PyObject* reset(PyObject*)
    {
        SniffWindow::window->lb_cmd->clear();
        return Py_None;
    }

    PyObject* open(PyObject*, PyObject* args)
    {
        char* str = NULL;
        if (!PyArg_ParseTuple(args, "s", &str))
        {
            return NULL;
        }
        SniffWindow::window->runOfflineFile(str);
        return Py_None;
    }

    PyObject* stop(PyObject*)
    {
        SniffWindow::window->on_actionStop_triggered();
        return Py_None;
    }

    PyObject* exit(PyObject*)
    {
        SniffWindow::window->close();
        return Py_None;
    }

    static PyMethodDef methods[] =
    {
        { "reset", (PyCFunction)reset, METH_NOARGS, NULL },
        { "open", (PyCFunction)open, METH_VARARGS, NULL },
        { "stop", (PyCFunction)stop, METH_NOARGS, NULL },
        { "exit", (PyCFunction)exit, METH_NOARGS, NULL },
        { NULL, NULL, 0, NULL }
    };

#if PY_MAJOR_VERSION >= 3
    static PyModuleDef module =
    {
        PyModuleDef_HEAD_INIT, "_hs_ui", NULL, -1, methods, NULL, NULL, NULL, NULL
    };
#endif

    static initModuleReturn PyInit_hs_ui(void)
    {
#if PY_MAJOR_VERSION < 3
        Py_InitModule("_hs_ui", methods);
#else
        return PyModule_Create(&module);
#endif
    }
}

namespace catchOutErr {

    struct catchOutErr
    {
        PyObject_HEAD
        char* color;
    };

    static void CatchOutErr_dealloc(catchOutErr* self)
    {
        free(self->color);
        Py_TYPE(self)->tp_free((PyObject*)self);
    }

    static PyObject* CatchOutErr_new(PyTypeObject* type, PyObject*, PyObject*)
    {
        catchOutErr* self;

        self = (catchOutErr*)type->tp_alloc(type, 0);
        if (self != NULL)
        {
            self->color = NULL;
        }

        return (PyObject*)self;
    }

    static int CatchOutErr_init(catchOutErr* self, PyObject* args, PyObject*)
    {
        const char* color = NULL;
        if (!PyArg_ParseTuple(args, "s", &color))
        {
            return -1;
        }
        self->color = (char*)malloc(strlen(color));
        strcpy(self->color, color);

        return 0;
    }

    static PyObject* CatchOutErr_write(catchOutErr* self, PyObject* args)
    {
        char* str = NULL;
        if (!PyArg_ParseTuple(args, "s", &str))
        {
            return NULL;
        }
        QPlainTextEdit* cmd = SniffWindow::window->lb_cmd;
        cmd->moveCursor(QTextCursor::End);
        cmd->textCursor().insertHtml(QStringLiteral("<font color=\"%1\">%2</font>").arg(self->color).arg(str).replace("\n", "<br/>"));
        cmd->moveCursor(QTextCursor::End);
        return Py_None;
    }

    static PyMethodDef CatchOutErr_methods[] =
    {
        {"write", (PyCFunction)CatchOutErr_write, METH_VARARGS, NULL},
        { NULL, NULL, 0, NULL }
    };

#ifdef Q_CC_GNU
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wmissing-field-initializers"
#endif
    static PyTypeObject type =
    {
        PyVarObject_HEAD_INIT(NULL, 0)
        "", sizeof(catchOutErr), 0,
        (destructor)CatchOutErr_dealloc,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        Py_TPFLAGS_DEFAULT, NULL, 0, 0, 0, 0, 0, 0, CatchOutErr_methods,
        0, 0, 0, 0, 0, 0, 0, (initproc)CatchOutErr_init, 0, CatchOutErr_new
    };
#ifdef Q_CC_GNU
    #pragma GCC diagnostic pop
#endif

    static void redirect(PyObject* sys)
    {
        PyType_Ready(&type);
        Py_INCREF(&type);

        PyObject* argList = Py_BuildValue("(s)", "blue");
        PyObject_SetAttrString(sys, "stdout", PyObject_CallObject((PyObject*)&type, argList));
        Py_DECREF(argList);

        argList = Py_BuildValue("(s)", "red");
        PyObject_SetAttrString(sys, "stderr", PyObject_CallObject((PyObject*)&type, argList));
        Py_DECREF(argList);
    }

}

static void addDirToPath(PyObject* sys, const char* path)
{
    PyObject* sys_path = PyObject_GetAttrString(sys, "path");
    PyObject* folder_path = GetPyString(path);
    PyList_Append(sys_path, folder_path);

    QSettings& settings = *Preferences::settings;
    settings.beginGroup(QStringLiteral("General"));
    settings.beginGroup(QStringLiteral("Modules"));
    QVariant var = settings.value(QStringLiteral("python_dir"));
    if(!var.isNull())
    {
        for(const QString& p : var.toStringList())
        {
            folder_path = GetPyString(p.toUtf8().constData());
            PyList_Append(sys_path, folder_path);
        }
    }
    settings.endGroup();
    settings.endGroup();
}

void SniffWindow::stopPython()
{
    Py_Finalize();
}

void SniffWindow::initPython(QLabel* img_python)
{
#ifdef _MSC_VER
    img_python->setToolTip(QStringLiteral("Python ").append(PY_VERSION));
#else
    img_python->setToolTip(QStringLiteral("Python " PY_VERSION));
#endif

    PyImport_AppendInittab("_hs_private", &hs::PyInit_hs);
    PyImport_AppendInittab("_hs_ui", &ui::PyInit_hs_ui);
    Py_Initialize();

    PyObject* sys = PyImport_ImportModule("sys");

    addDirToPath(sys, getPythonPath());

    PyObject* mainModule = PyImport_AddModule("__main__");
    PyObject* hsModule = PyImport_ImportModule("hs");
    hs::filter::init(hsModule);
    hs::packet::layer::init(hsModule);
    PyModule_AddObject(mainModule, "hs", hsModule);

    PyObject* globals = (PyObject*)(this->pyGlobals = PyModule_GetDict(mainModule));
    PyRun_String("from _hs_ui import *", Py_single_input, globals, globals);
    catchOutErr::redirect(sys);

    this->py_checkCommand.reset();
}

void SniffWindow::addPyCommand(const char* command)
{
    QString output;
    if(this->pyCommand.length() == 0)
        output.append("&gt;&gt;&gt; ");
    else
        output.append(".  .  . ");
    output.append("<font color=\"green\">");
    output.append(QString(command).replace("<", "&lt;").replace(">", "&gt;"));
    output.append("</font><br />");
    lb_cmd->moveCursor(QTextCursor::End);
    lb_cmd->textCursor().insertHtml(output);
    lb_cmd->moveCursor(QTextCursor::End);
    tb_command->clear();

    if(command[0] == '\0' && !this->py_checkCommand.block)
        return;

    this->pyCommand.push_back('\n');
    this->pyCommand.append(command);

    if(this->checkPyCommand(command))
    {
        PyRun_String(this->pyCommand.c_str(), Py_single_input, (PyObject*)pyGlobals, (PyObject*)pyGlobals);
        if (PyErr_Occurred())
        {
            PyErr_Print();
            PyErr_Clear();
        }

        this->py_checkCommand.reset();
        this->pyCommand.clear();
    }
}

bool SniffWindow::checkPyCommand(const char* command)
{
    bool lineDelimeter = true;
    bool posibleBlock = !py_checkCommand.block;
    bool isFinished = true;

    const char* c = strrchr(command, '#');
    if(!c)
        c = command + strlen(command) - 1;
    else
        c--;

    for (; isFinished && c >= command; --c)
    {
        if (*c != ' ' && *c != '\\')
            lineDelimeter = false;
        if (*c != ' ' && *c != ':')
            posibleBlock = false;
        switch (*c)
        {
            case ')':
                py_checkCommand.bracketsC++;
                break;
            case '(':
                py_checkCommand.bracketsC--;
                break;
            case ']':
                py_checkCommand.bracketsS++;
                break;
            case '[':
                py_checkCommand.bracketsS--;
                break;
            case '}':
                py_checkCommand.bracketsM++;
                break;
            case '{':
                py_checkCommand.bracketsM--;
                break;
            case '\"':
                for (c -= 1; c >= command; --c)
                    if (c[0] == '\"' && c[-1] != '\\')
                        break;
                break;
            case '\'':
                for (c -= 1; c >= command; --c)
                    if (c[0] == '\'' && c[-1] != '\\')
                        break;
                break;
            case '\\':
                isFinished &= !lineDelimeter;
                break;
            case ':':
                py_checkCommand.block |= posibleBlock;
                break;
        }
    }
    isFinished &= (py_checkCommand.bracketsC >= 0) & (py_checkCommand.bracketsS >= 0) & (py_checkCommand.bracketsM >= 0);
    isFinished &= !(py_checkCommand.block & (*command != '\0'));

    return isFinished;
}

void SniffWindow::tb_command_returnPressed()
{
    this->addPyCommand(tb_command->text().toUtf8().constData());
}

#endif
