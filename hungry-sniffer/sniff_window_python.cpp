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
    #define GetPyString PyString_FromString
#else
    #define GetPyString PyUnicode_FromString
#endif

#ifdef Q_OS_WIN
    int gettimeofday(struct timeval* tv, struct timezone*);
#endif

namespace hs {
    PyObject* savePacket(PyObject*, PyObject* args)
    {
        int size;
        const char* b;
#if PY_MAJOR_VERSION < 3
        if (!PyArg_ParseTuple(args, "s#", &b, &size))
        {
            return NULL;
        }
#else
        PyObject* data;
        if (!PyArg_ParseTuple(args, "Y", &data))
        {
            return NULL;
        }
        size = PyByteArray_Size(data);
        b = PyByteArray_AsString(data);
#endif

        DataStructure::RawPacketData raw;
        gettimeofday(&raw.time, nullptr);
        raw.setData(b, size);
        SniffWindow::window->toAdd.push(raw);
        return Py_None;
    }

    static PyMethodDef methods[] =
    {
        { "addPacket", (PyCFunction)savePacket, METH_VARARGS, NULL },
        { NULL, NULL, 0, NULL }
    };

#if PY_MAJOR_VERSION >= 3
    static PyModuleDef module =
    {
        PyModuleDef_HEAD_INIT, "hs", NULL, -1, methods, NULL, NULL, NULL, NULL
    };
#endif

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
                    PyDict_SetItem(self->headers, GetPyString(i.key.c_str()), GetPyString(i.value.c_str()));

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
        }

        struct packet_obj
        {
            PyObject_HEAD
            int num;
            bool isShown;
            float time;
            PyObject* data;
            PyObject* layersArr;
        };

        static void packet_dealloc(packet_obj* self)
        {
            Py_XDECREF(self->layersArr);
            Py_XDECREF(self->data);
            Py_TYPE(self)->tp_free((PyObject*)self);
        }

        static PyObject* packet_new(PyTypeObject* type, PyObject*, PyObject*)
        {
            packet_obj* self;

            self = (packet_obj*)type->tp_alloc(type, 0);
            if (self != NULL)
            {
                self->num = 0;
                self->time = 0;
                self->isShown = false;
                self->data = Py_None;
                self->layersArr = Py_None;
            }

            return (PyObject*)self;
        }

        static int packet_init(packet_obj* self, PyObject* args, PyObject*)
        {
            int row;

            if (!PyArg_ParseTuple(args, "i", &row))
            {
                return -1;
            }

            const DataStructure::localPacket& pack = SniffWindow::window->model.local[row];
            self->num = row;
            self->isShown = pack.isShown;
            self->time = pack.rawPacket.time.tv_sec + (float)pack.rawPacket.time.tv_usec * 0.000001;

#if PY_MAJOR_VERSION < 3
            self->data = PyString_FromStringAndSize((const char*)pack.rawPacket.data, pack.rawPacket.len);
#else
            self->data = PyByteArray_FromStringAndSize((const char*)pack.rawPacket.data, pack.rawPacket.len);
#endif

            Py_XDECREF(self->layersArr);
            self->layersArr = PyList_New(0);
            int i = 0;
            for(const hungry_sniffer::Packet* packet = pack.decodedPacket; packet != nullptr; packet = packet->getNext(), i++)
            {
                PyObject* argList = Py_BuildValue("(ii)", row, i);
                PyObject* layer = PyObject_CallObject((PyObject*)&layer::type, argList);
                PyList_Append(self->layersArr, layer);
                Py_DECREF(layer);
                Py_DECREF(argList);
            }

            return 0;
        }

        static PyObject* packet_repr(packet_obj* self)
        {
#if PY_MAJOR_VERSION < 3
            PyObject* res = PyString_FromFormat("[%d - %s - [", self->num, (self->isShown ? "True" : "False"));
            Py_ssize_t len = PyList_Size(self->layersArr);
            for(Py_ssize_t i = 0; i < len; i++)
            {
                PyObject* lay = PyList_GET_ITEM(self->layersArr, i);
                PyString_Concat(&res, ((layer::layer_obj*)lay)->name);
                if(i != len - 1)
                    PyString_ConcatAndDel(&res, PyString_FromString(", "));
            }
            PyString_ConcatAndDel(&res, PyString_FromString("]]"));
            return res;
#else
            PyObject* res = PyUnicode_FromFormat("[%d - %s - [", self->num, (self->isShown ? "True" : "False"));
            Py_ssize_t len = PyList_Size(self->layersArr);
            for(Py_ssize_t i = 0; i < len; i++)
            {
                PyObject* lay = PyList_GET_ITEM(self->layersArr, i);
                PyUnicode_Append(&res, ((layer::layer_obj*)lay)->name);
                if(i != len - 1)
                    PyUnicode_AppendAndDel(&res, PyUnicode_FromString(", "));
            }
            PyUnicode_AppendAndDel(&res, PyUnicode_FromString("]]"));
            return res;
#endif
        }

        static PyObject* packet_str(packet_obj* self)
        {
#if PY_MAJOR_VERSION < 3
            PyObject* res = PyString_FromFormat("#%d\n%s\n", self->num, (self->isShown ? "True" : "False"));
            Py_ssize_t len = PyList_Size(self->layersArr);
            for(Py_ssize_t i = 0; i < len; i++)
            {
                PyObject* lay = PyList_GET_ITEM(self->layersArr, i);
                PyString_Concat(&res, ((layer::layer_obj*)lay)->name);
                if(i != len - 1)
                    PyString_ConcatAndDel(&res, PyString_FromString(" -> "));
            }
            PyString_ConcatAndDel(&res, PyString_FromString("\n"));
            return res;
#else
            PyObject* res = PyUnicode_FromFormat("#%d\n%s\n", self->num, (self->isShown ? "Shown" : "not Shown"));
            Py_ssize_t len = PyList_Size(self->layersArr);
            for(Py_ssize_t i = 0; i < len; i++)
            {
                PyObject* lay = PyList_GET_ITEM(self->layersArr, i);
                PyUnicode_Append(&res, ((layer::layer_obj*)lay)->name);
                if(i != len - 1)
                    PyUnicode_AppendAndDel(&res, PyUnicode_FromString(" -> "));
            }
            PyUnicode_AppendAndDel(&res, PyUnicode_FromString("\n"));
            return res;
#endif
        }

        static PyMemberDef packet_members[] =
        {
            {(char*)"num", T_INT, offsetof(packet_obj, num), READONLY, NULL},
            {(char*)"isShown", T_BOOL, offsetof(packet_obj, isShown), READONLY, NULL},
            {(char*)"time", T_FLOAT, offsetof(packet_obj, time), READONLY, NULL},
            {(char*)"data", T_OBJECT, offsetof(packet_obj, data), 0, NULL},
            {(char*)"layersArr", T_OBJECT, offsetof(packet_obj, layersArr), READONLY, NULL},
            {NULL, 0, 0, 0, NULL}
        };

        static PyObject* packet_remove(packet_obj* self)
        {
            SniffWindow::window->model.remove(self->num);
            SniffWindow::window->ui->statusBar->updateText();
            return Py_None;
        }

        static PyObject* packet_save(packet_obj* self, PyObject* args)
        {
            Py_ssize_t size = 0;
            char* b = NULL;
            PyObject* data = self->data;
#if PY_MAJOR_VERSION < 3
            if (!PyArg_ParseTuple(args, "|O", &data))
            {
                return NULL;
            }
            PyString_AsStringAndSize(data, &b, &size);
#else
            if (!PyArg_ParseTuple(args, "|Y", &data))
            {
                return NULL;
            }

            size = PyByteArray_Size(data);
            b = PyByteArray_AsString(data);
#endif
            if(data != self->data)
            {
                Py_INCREF(data);
                Py_XDECREF(self->data);
                self->data = data;
            }

            struct DataStructure::localPacket& pack = SniffWindow::window->model.local[self->num];
            DataStructure::RawPacketData& raw = pack.rawPacket;
            free(raw.data);
            raw.setData(b, size);

            delete pack.decodedPacket;
            pack.decodedPacket = new hungry_sniffer::EthernetPacket(raw.data, raw.len, &HungrySniffer_Core::core->base);

            SniffWindow::window->updateTableShown();
            return Py_None;
        }

        static PyMethodDef packet_methods[] =
        {
            {"remove", (PyCFunction)packet_remove, METH_NOARGS, NULL},
            {"save", (PyCFunction)packet_save, METH_VARARGS, NULL},
            { NULL, NULL, 0, NULL }
        };

        static Py_ssize_t packet_len(packet_obj* self)
        {
            return PyList_Size(self->layersArr);
        }

        static PyObject* packet_itemAt(packet_obj* self, PyObject* key)
        {
            PyObject* res = NULL;
#if PY_MAJOR_VERSION < 3
            if(PyInt_CheckExact(key))
                res = PyList_GetItem(self->layersArr, PyInt_AsSsize_t(key));
            else if(PyString_CheckExact(key))
#else
            if(PyLong_CheckExact(key))
                res = PyList_GetItem(self->layersArr, PyLong_AsSsize_t(key));
            else if(PyUnicode_CheckExact(key))
#endif
            {
                Py_ssize_t len = PyList_Size(self->layersArr);
                for(Py_ssize_t i = 0; i < len; i++)
                {
                    PyObject* lay = PyList_GET_ITEM(self->layersArr, i);
#if PY_MAJOR_VERSION < 3
                    if(strcmp(PyString_AS_STRING(key), PyString_AS_STRING(((layer::layer_obj*)lay)->name)) == 0)
#else
                    if(PyUnicode_Compare(key, ((layer::layer_obj*)lay)->name) == 0)
#endif
                    {
                        res = lay;
                        break;
                    }
                }
                if(res == NULL)
                    return Py_None;
            }
            Py_XINCREF(res);
            return res;
        }

        static PyMappingMethods packet_map =
        {
            (lenfunc)packet_len,
            (binaryfunc)packet_itemAt,
            0
        };

#ifdef Q_CC_GNU
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wmissing-field-initializers"
#endif
        static PyTypeObject type =
        {
            PyVarObject_HEAD_INIT(NULL, 0)
            "", sizeof(packet_obj), 0,
            (destructor)packet_dealloc,
            0, 0, 0, 0, (reprfunc)packet_repr, 0, 0, &packet_map, 0, 0, (reprfunc)packet_str, 0, 0, 0,
            Py_TPFLAGS_DEFAULT, NULL, 0, 0, 0, 0, 0, 0, packet_methods,
            packet_members, 0, 0, 0, 0, 0, 0, (initproc)packet_init, 0, packet_new
        };

#ifdef Q_CC_GNU
    #pragma GCC diagnostic pop
#endif
        static void init()
        {
            PyType_Ready(&layer::type);
            Py_INCREF(&layer::type);

            PyType_Ready(&type);
            Py_INCREF(&type);
        }
    }

    namespace all_packets {

        struct iter_obj
        {
            PyObject_HEAD
            unsigned current;
        };

        PyObject* all_iter_iter(PyObject* self)
        {
            Py_INCREF(self);
            return self;
        }

        static PyObject* all_iter_iternext(iter_obj* self)
        {
            unsigned row = (self->current++);
            if(row < SniffWindow::window->model.local.size())
            {
                PyObject* argList = Py_BuildValue("(i)", row);
                PyObject* tmp = PyObject_CallObject((PyObject*)&hs::packet::type, argList);
                Py_DECREF(argList);
                return tmp;
            }
            PyErr_SetNone(PyExc_StopIteration);
            return NULL;
        }

#ifdef Q_CC_GNU
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wmissing-field-initializers"
#endif
        static PyTypeObject iter_type =
        {
            PyVarObject_HEAD_INIT(NULL, 0)
            "", sizeof(iter_obj), 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            Py_TPFLAGS_DEFAULT, NULL, 0, 0, 0, 0, (getiterfunc)all_iter_iter, (getiterfunc)all_iter_iternext, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        };
#ifdef Q_CC_GNU
    #pragma GCC diagnostic pop
#endif
        struct all_obj
        {
            PyObject_HEAD
        };

        PyObject* all_iter(PyObject*)
        {
            iter_obj* iter;
            iter = PyObject_New(iter_obj, &iter_type);
            if(iter == NULL)
                return NULL;
            iter->current = 0;
            return (PyObject*)iter;
        }

        Py_ssize_t all_len(PyObject*)
        {
            return SniffWindow::window->model.local.size();
        }

        PyObject* all_item(PyObject*, Py_ssize_t index)
        {
            if(index >= (Py_ssize_t)SniffWindow::window->model.local.size())
            {
                PyErr_SetNone(PyExc_IndexError);
                return NULL;
            }
            PyObject* argList = Py_BuildValue("(i)", index);
            PyObject* tmp = PyObject_CallObject((PyObject*)&hs::packet::type, argList);
            Py_DECREF(argList);
            return tmp;
        }

#ifdef Q_CC_GNU
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wmissing-field-initializers"
#endif
        static PySequenceMethods seq_methods =
        {
            all_len,
            0,
            0,
            all_item
        };

        static PyTypeObject all_type =
        {
            PyVarObject_HEAD_INIT(NULL, 0)
            "", sizeof(all_obj), 0,
            0,
            0, 0, 0, 0, 0, 0, &seq_methods, 0, 0, 0, 0, 0, 0, 0,
            Py_TPFLAGS_DEFAULT, NULL, 0, 0, 0, 0, (getiterfunc)all_iter, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        };
#ifdef Q_CC_GNU
    #pragma GCC diagnostic pop
#endif
        static void init(PyObject* hsModule)
        {
            PyType_Ready(&iter_type);
            PyType_Ready(&all_type);

            Py_INCREF(&iter_type);
            Py_INCREF(&all_type);

            PyObject* all = PyObject_New(PyObject, &all_type);
            PyModule_AddObject(hsModule, "all", all);
        }
    }

    namespace shown_packets {

        struct iter_obj
        {
            PyObject_HEAD
            unsigned current;
        };

        PyObject* shown_iter_iter(PyObject* self)
        {
            Py_INCREF(self);
            return self;
        }

        static PyObject* shown_iter_iternext(iter_obj* self)
        {
            unsigned row = (self->current++);
            const auto& shown = SniffWindow::window->model.shownPerRow;
            if(row < shown.size())
            {
                PyObject* argList = Py_BuildValue("(i)", shown[row]);
                PyObject* tmp = PyObject_CallObject((PyObject*)&hs::packet::type, argList);
                Py_DECREF(argList);
                return tmp;
            }
            PyErr_SetNone(PyExc_StopIteration);
            return NULL;
        }

#ifdef Q_CC_GNU
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wmissing-field-initializers"
#endif
        static PyTypeObject iter_type =
        {
            PyVarObject_HEAD_INIT(NULL, 0)
            "", sizeof(iter_obj), 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            Py_TPFLAGS_DEFAULT, NULL, 0, 0, 0, 0, (getiterfunc)shown_iter_iter, (getiterfunc)shown_iter_iternext, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        };
#ifdef Q_CC_GNU
    #pragma GCC diagnostic pop
#endif
        struct shown_obj
        {
            PyObject_HEAD
        };

        PyObject* shown_iter(PyObject*)
        {
            iter_obj* iter;
            iter = PyObject_New(iter_obj, &iter_type);
            if(iter == NULL)
                return NULL;
            iter->current = 0;
            return (PyObject*)iter;
        }

        Py_ssize_t shown_len(PyObject*)
        {
            return SniffWindow::window->model.shownPerRow.size();
        }

        PyObject* shown_item(PyObject*, Py_ssize_t index)
        {
            const auto& shown = SniffWindow::window->model.shownPerRow;
            if(index >= (Py_ssize_t)shown.size())
            {
                PyErr_SetNone(PyExc_IndexError);
                return NULL;
            }
            PyObject* argList = Py_BuildValue("(i)", shown[index]);
            PyObject* tmp = PyObject_CallObject((PyObject*)&hs::packet::type, argList);
            Py_DECREF(argList);
            return tmp;
        }

#ifdef Q_CC_GNU
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wmissing-field-initializers"
#endif
        static PySequenceMethods seq_methods =
        {
            shown_len,
            0,
            0,
            shown_item
        };

        static PyTypeObject shown_type =
        {
            PyVarObject_HEAD_INIT(NULL, 0)
            "", sizeof(shown_obj), 0,
            0,
            0, 0, 0, 0, 0, 0, &seq_methods, 0, 0, 0, 0, 0, 0, 0,
            Py_TPFLAGS_DEFAULT, NULL, 0, 0, 0, 0, (getiterfunc)shown_iter, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        };
#ifdef Q_CC_GNU
    #pragma GCC diagnostic pop
#endif
        static void init(PyObject* hsModule)
        {
            PyType_Ready(&iter_type);
            PyType_Ready(&shown_type);

            Py_INCREF(&iter_type);
            Py_INCREF(&shown_type);

            PyObject* shown = PyObject_New(PyObject, &shown_type);
            PyModule_AddObject(hsModule, "shown", shown);
        }
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
        PyModuleDef_HEAD_INIT, "__main__", NULL, -1, methods, NULL, NULL, NULL, NULL
    };
#endif
}

namespace catchOutErr {

    struct catch_obj
    {
        PyObject_HEAD
        const char* color;
    };

    static PyObject* CatchOutErr_write(catch_obj* self, PyObject* args)
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
        "", sizeof(catch_obj), 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        Py_TPFLAGS_DEFAULT, NULL, 0, 0, 0, 0, 0, 0, CatchOutErr_methods,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };
#ifdef Q_CC_GNU
    #pragma GCC diagnostic pop
#endif

    static void redirect(PyObject* sys)
    {
        PyType_Ready(&type);
        Py_INCREF(&type);

        catch_obj* t = PyObject_New(catch_obj, &type);
        t->color = "blue";
        PyObject_SetAttrString(sys, "stdout", (PyObject*)t);
        Py_DECREF(t);

        t = PyObject_New(catch_obj, &type);
        t->color = "red";
        PyObject_SetAttrString(sys, "stderr", (PyObject*)t);
        Py_DECREF(t);
    }

}

static void addDirToPath(PyObject* sys)
{
    PyObject* sys_path = PyObject_GetAttrString(sys, "path");

    QSettings& settings = *Preferences::settings;
    settings.beginGroup(QStringLiteral("General"));
    settings.beginGroup(QStringLiteral("Modules"));
    QVariant var = settings.value(QStringLiteral("python_dir"));
    if(!var.isNull())
    {
        for(const QString& p : var.toStringList())
        {
            PyObject* folder_path = GetPyString(p.toUtf8().constData());
            PyList_Append(sys_path, folder_path);
            Py_DECREF(folder_path);
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
#ifdef Q_CC_MSVC
    img_python->setToolTip(QStringLiteral("Python ").append(PY_VERSION));
#else
    img_python->setToolTip(QStringLiteral("Python " PY_VERSION));
#endif

    Py_Initialize();

    PyObject* sys = PyImport_ImportModule("sys");
    addDirToPath(sys);
    catchOutErr::redirect(sys);

#if PY_MAJOR_VERSION < 3
    PyObject* mainModule = Py_InitModule("__main__", ui::methods);
    PyObject* hsModule = Py_InitModule("hs", hs::methods);
#else
    PyObject* mainModule = PyModule_Create(&ui::module);
    PyModule_AddObject(mainModule, "__builtins__", PyEval_GetBuiltins());
    PyObject* hsModule = PyModule_Create(&hs::module);
#endif

    hs::filter::init(hsModule);
    hs::packet::init();
    hs::all_packets::init(hsModule);
    hs::shown_packets::init(hsModule);
    PyModule_AddObject(mainModule, "hs", hsModule);

    this->pyGlobals = PyModule_GetDict(mainModule);
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
