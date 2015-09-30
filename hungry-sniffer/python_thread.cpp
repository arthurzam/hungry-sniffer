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
#include "EthernetPacket.h"
#include "preferences.h"

#include <QPlainTextEdit>
#include <QSettings>
#include <hs_core.h>
#include "python_thread.h"

#if PY_MAJOR_VERSION < 3
    #define GetPyString PyString_FromString

    #define GetPyBuffer_SizeString PyString_FromStringAndSize
    #define GetPyBuffer_getSize PyString_GET_SIZE
    #define GetPyBuffer_getData PyString_AS_STRING
#else
    #define GetPyString PyUnicode_FromString

    #define GetPyBuffer_SizeString PyByteArray_FromStringAndSize
    #define GetPyBuffer_getSize PyByteArray_GET_SIZE
    #define GetPyBuffer_getData PyByteArray_AS_STRING
#endif

#ifdef Q_OS_WIN
    int gettimeofday(struct timeval* tv, struct timezone*);
#endif

namespace hs {
    PyObject* addPacket(PyObject*, PyObject* args)
    {
        int size;
        const char* b;
#if PY_MAJOR_VERSION < 3
        if (!PyArg_ParseTuple(args, "s#", &b, &size))
            return NULL;
#else
        PyObject* data;
        if (!PyArg_ParseTuple(args, "Y", &data))
            return NULL;
        size = PyByteArray_GET_SIZE(data);
        b = PyByteArray_AS_STRING(data);
#endif

        DataStructure::RawPacketData raw;
        gettimeofday(&raw.time, nullptr);
        raw.setData(b, size);
        SniffWindow::window->toAdd.push(raw);
        Py_RETURN_NONE;
    }

    static PyMethodDef methods[] =
    {
        { "addPacket", (PyCFunction)addPacket, METH_VARARGS, NULL },
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
                const char* name;
                PyObject* info;
                PyObject* headers;
            };

            static void layer_dealloc(layer_obj* self)
            {
                Py_XDECREF(self->info);
                Py_DECREF(self->headers);
                Py_TYPE(self)->tp_free((PyObject*)self);
            }

            static PyMemberDef layer_members[] =
            {
                {(char*)"name", T_STRING, offsetof(layer_obj, name), READONLY, NULL},
                {(char*)"info", T_OBJECT, offsetof(layer_obj, info), READONLY, NULL},
                {(char*)"headers", T_OBJECT_EX, offsetof(layer_obj, headers), READONLY, NULL},
                {NULL, 0, 0, 0, NULL}
            };

            static PyObject* layer_repr(layer_obj* self)
            {
                if(self->info == NULL)
                {
                    return GetPyString(self->name);
                }
#if PY_MAJOR_VERSION < 3
                return PyString_FromFormat("[%s - %s]", PyString_AS_STRING(self->name), PyString_AS_STRING(self->info));
#else
                return PyUnicode_FromFormat("[%U - %U]", self->name, self->info);
#endif
            }

            static PyObject* layer_str(layer_obj* self)
            {
#if PY_MAJOR_VERSION < 3
                PyObject* res = PyString_FromFormat("%s\n%s\n", self->name, self->info ? PyString_AS_STRING(self->info) : "");
#else
                PyObject* res = PyUnicode_FromFormat("%s\n%V\n", self->name, self->info, "");
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
                "", sizeof(layer_obj), 0, (destructor)layer_dealloc, 0, 0, 0, 0,
                (reprfunc)layer_repr, 0, 0, &layer_map, 0, 0, (reprfunc)layer_str, 0, 0, 0,
                Py_TPFLAGS_DEFAULT, NULL, 0, 0, 0, 0, 0, 0, 0,
                layer_members, 0, 0, 0, 0, 0, 0, 0, 0, 0
            };

#ifdef Q_CC_GNU
    #pragma GCC diagnostic pop
#endif
        }

        struct packet_obj
        {
            PyObject_HEAD
            PyObject* data;
            PyObject* layersArr;
            unsigned num;
            unsigned len;
            float time;
            bool isShown;
        };

        static void packet_dealloc(packet_obj* self)
        {
            Py_DECREF(self->layersArr);
            Py_XDECREF(self->data);
            Py_TYPE(self)->tp_free((PyObject*)self);
        }

        static PyObject* packet_repr(packet_obj* self)
        {
#if PY_MAJOR_VERSION < 3
            PyObject* res = PyString_FromFormat("[%d - %s - [", self->num, (self->isShown ? "True" : "False"));
            Py_ssize_t len = PyList_GET_SIZE(self->layersArr);
            for(Py_ssize_t i = 0; i < len; i++)
            {
                PyObject* lay = PyList_GET_ITEM(self->layersArr, i);
                PyString_ConcatAndDel(&res, PyString_FromString(((layer::layer_obj*)lay)->name));
                if(i != len - 1)
                    PyString_ConcatAndDel(&res, PyString_FromString(", "));
            }
            PyString_ConcatAndDel(&res, PyString_FromString("]]"));
            return res;
#else
            PyObject* res = PyUnicode_FromFormat("[%d - %s - [", self->num, (self->isShown ? "True" : "False"));
            Py_ssize_t len = PyList_GET_SIZE(self->layersArr);
            for(Py_ssize_t i = 0; i < len; i++)
            {
                PyObject* lay = PyList_GET_ITEM(self->layersArr, i);
                PyUnicode_AppendAndDel(&res, GetPyString(((layer::layer_obj*)lay)->name));
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
            Py_ssize_t len = PyList_GET_SIZE(self->layersArr);
            for(Py_ssize_t i = 0; i < len; i++)
            {
                PyObject* lay = PyList_GET_ITEM(self->layersArr, i);
                PyString_ConcatAndDel(&res, PyString_FromString(((layer::layer_obj*)lay)->name));
                if(i != len - 1)
                    PyString_ConcatAndDel(&res, PyString_FromString(" -> "));
            }
            PyString_ConcatAndDel(&res, PyString_FromString("\n"));
            return res;
#else
            PyObject* res = PyUnicode_FromFormat("#%d\n%s\n", self->num, (self->isShown ? "Shown" : "not Shown"));
            Py_ssize_t len = PyList_GET_SIZE(self->layersArr);
            for(Py_ssize_t i = 0; i < len; i++)
            {
                PyObject* lay = PyList_GET_ITEM(self->layersArr, i);
                PyUnicode_AppendAndDel(&res, GetPyString(((layer::layer_obj*)lay)->name));
                if(i != len - 1)
                    PyUnicode_AppendAndDel(&res, PyUnicode_FromString(" -> "));
            }
            PyUnicode_AppendAndDel(&res, PyUnicode_FromString("\n"));
            return res;
#endif
        }

        static PyMemberDef packet_members[] =
        {
            {(char*)"num", T_UINT, offsetof(packet_obj, num), READONLY, NULL},
            {(char*)"isShown", T_BOOL, offsetof(packet_obj, isShown), READONLY, NULL},
            {(char*)"time", T_FLOAT, offsetof(packet_obj, time), READONLY, NULL},
            {(char*)"len", T_UINT, offsetof(packet_obj, len), READONLY, NULL},
            {(char*)"layersArr", T_OBJECT, offsetof(packet_obj, layersArr), READONLY, NULL},
            {NULL, 0, 0, 0, NULL}
        };

        static PyObject* packet_getData(packet_obj* self, void*)
        {
            if(self->data == NULL)
            {
                const auto& all = SniffWindow::window->model.local;
                if(all.size() <= self->num)
                    return NULL;
                const DataStructure::localPacket& pack = all[self->num];
                self->data = GetPyBuffer_SizeString((const char*)pack.rawPacket.data, pack.rawPacket.len);
            }
            Py_INCREF(self->data);
            return self->data;
        }

        static int packet_setData(packet_obj* self, PyObject* value, void*)
        {
            if (value == NULL)
            {
                PyErr_SetString(PyExc_TypeError, "Cannot delete the last attribute");
                return -1;
            }

#if PY_MAJOR_VERSION < 3
            if (!PyString_Check(value))
            {
                PyErr_SetString(PyExc_TypeError, "The last attribute value must be a string");
                return -1;
            }
#else
            if (!PyByteArray_Check(value))
            {
                PyErr_SetString(PyExc_TypeError, "The last attribute value must be a bytearray");
                return -1;
            }
#endif

            Py_XDECREF(self->data);
            Py_INCREF(value);
            self->data = value;
            self->len = GetPyBuffer_getSize(self->data);
            return 0;
        }

        static PyGetSetDef packet_getset[] = {
            {(char*)"data", (getter)packet_getData, (setter)packet_setData, NULL, NULL},
            {NULL, NULL, NULL, NULL, NULL}
        };

        static PyObject* packet_remove(packet_obj* self)
        {
            SniffWindow::window->model.remove(self->num);
            SniffWindow::window->ui->statusBar->updateText();
            Py_RETURN_NONE;
        }

        static PyObject* packet_save(packet_obj* self)
        {
            if(self->data == NULL)
                Py_RETURN_NONE;
            Py_ssize_t size = 0;
            char* b = NULL;
            size = GetPyBuffer_getSize(self->data);
            b = GetPyBuffer_getData(self->data);
            auto& all = SniffWindow::window->model.local;
            if(all.size() <= self->num)
                return NULL;
            DataStructure::localPacket& pack = all[self->num];
            DataStructure::RawPacketData& raw = pack.rawPacket;
            free(raw.data);
            raw.setData(b, size);

            delete pack.decodedPacket;
            pack.decodedPacket = new hungry_sniffer::EthernetPacket(raw.data, size, &HungrySniffer_Core::core->base);

            SniffWindow::window->updateTableShown();
            Py_RETURN_NONE;
        }

        static PyMethodDef packet_methods[] =
        {
            {"remove", (PyCFunction)packet_remove, METH_NOARGS, NULL},
            {"save", (PyCFunction)packet_save, METH_VARARGS, NULL},
            { NULL, NULL, 0, NULL }
        };

        static Py_ssize_t packet_len(packet_obj* self)
        {
            return PyList_GET_SIZE(self->layersArr);
        }

        static PyObject* packet_itemAt(packet_obj* self, PyObject* key)
        {
            PyObject* res = NULL;
#if PY_MAJOR_VERSION < 3
            if(PyInt_CheckExact(key))
                res = PyList_GET_ITEM(self->layersArr, PyInt_AsSsize_t(key));
            else if(PyString_CheckExact(key))
#else
            if(PyLong_CheckExact(key))
                res = PyList_GET_ITEM(self->layersArr, PyLong_AsSsize_t(key));
            else if(PyUnicode_CheckExact(key))
#endif
            {
                Py_ssize_t len = PyList_GET_SIZE(self->layersArr);
                for(Py_ssize_t i = 0; i < len; i++)
                {
                    PyObject* lay = PyList_GET_ITEM(self->layersArr, i);
#if PY_MAJOR_VERSION < 3
                    if(strcmp(PyString_AS_STRING(key), ((layer::layer_obj*)lay)->name) == 0)
#else
                    if(PyUnicode_CompareWithASCIIString(key, ((layer::layer_obj*)lay)->name) == 0)
#endif
                    {
                        res = lay;
                        break;
                    }
                }
                if(res == NULL)
                {
                    PyErr_SetString(PyExc_KeyError, "protocol name not found");
                    return NULL;
                }
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
            "", sizeof(packet_obj), 0, (destructor)packet_dealloc, 0, 0, 0,
            0, (reprfunc)packet_repr, 0, 0, &packet_map, 0, 0, (reprfunc)packet_str, 0, 0, 0,
            Py_TPFLAGS_DEFAULT, NULL, 0, 0, 0, 0, 0, 0,
            packet_methods, packet_members, packet_getset
        };

#ifdef Q_CC_GNU
    #pragma GCC diagnostic pop
#endif
        static void init()
        {
            PyType_Ready(&layer::type);
            PyType_Ready(&type);
            Py_INCREF(&layer::type);
            Py_INCREF(&type);
        }

        static PyObject* buildPacket(int row)
        {
            packet_obj* obj = PyObject_New(packet_obj, &type);
            if(obj == NULL)
                return PyErr_NoMemory();

            const DataStructure::localPacket& pack = SniffWindow::window->model.local[row];
            obj->num = row;
            obj->isShown = pack.isShown;
            obj->time = pack.rawPacket.time.tv_sec + (float)pack.rawPacket.time.tv_usec * 0.000001f;
            obj->data = NULL;

            obj->layersArr = PyList_New(0);
            int i = 0;
            for(const hungry_sniffer::Packet* layer = pack.decodedPacket; layer != nullptr; layer = layer->getNext(), i++)
            {
                layer::layer_obj* layer_obj = PyObject_New(layer::layer_obj, &layer::type);
                if(layer_obj == NULL)
                    return PyErr_NoMemory();

                layer_obj->name = layer->getProtocol()->getName().c_str();
                const std::string& info = layer->getInfo();
                if(info.length())
                {
                    if((layer_obj->info = GetPyString(info.c_str())) == NULL)
                        return PyErr_NoMemory();
                }
                else
                    layer_obj->info = NULL;

                if((layer_obj->headers = PyDict_New()) == NULL)
                    return PyErr_NoMemory();
                for(auto& i : layer->getHeaders())
                {
                    PyObject* key = GetPyString(i.key.c_str());
                    if(key == NULL)
                        return PyErr_NoMemory();
                    PyObject* value = GetPyString(i.key.c_str());
                    if(value == NULL)
                        return PyErr_NoMemory();
                    PyDict_SetItem(layer_obj->headers, key, value);
                }

                PyList_Append(obj->layersArr, (PyObject*)layer_obj);
                Py_DECREF(layer_obj);
            }

            return (PyObject*)obj;
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
                return hs::packet::buildPacket(row);
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
            "", sizeof(iter_obj), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            Py_TPFLAGS_DEFAULT, NULL, 0, 0, 0, 0, (getiterfunc)all_iter_iter, (getiterfunc)all_iter_iternext,
        };
#ifdef Q_CC_GNU
    #pragma GCC diagnostic pop
#endif

        iter_obj* all_iter(PyObject*)
        {
            iter_obj* iter = PyObject_New(iter_obj, &iter_type);
            if(iter != NULL)
                iter->current = 0;
            return iter;
        }

        Py_ssize_t all_len(PyObject*)
        {
            return SniffWindow::window->model.local.size();
        }

        PyObject* all_item(PyObject*, Py_ssize_t index)
        {
            if(index >= (Py_ssize_t)SniffWindow::window->model.local.size())
            {
                PyErr_SetString(PyExc_IndexError, "index out of range");
                return NULL;
            }
            return hs::packet::buildPacket(index);
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
            "", sizeof(PyObject), 0, 0, 0, 0, 0, 0, 0, 0,
            &seq_methods, 0, 0, 0, 0, 0, 0, 0, Py_TPFLAGS_DEFAULT,
            NULL, 0, 0, 0, 0, (getiterfunc)all_iter
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

            PyModule_AddObject(hsModule, "all", PyObject_New(PyObject, &all_type));
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
                return hs::packet::buildPacket(shown[row]);
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
            "", sizeof(iter_obj), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            Py_TPFLAGS_DEFAULT, NULL, 0, 0, 0, 0, (getiterfunc)shown_iter_iter, (getiterfunc)shown_iter_iternext
        };
#ifdef Q_CC_GNU
    #pragma GCC diagnostic pop
#endif

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
                PyErr_SetString(PyExc_IndexError, "index out of range");
                return NULL;
            }
            return hs::packet::buildPacket(shown[index]);
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
            "", sizeof(PyObject), 0, 0, 0, 0, 0, 0, 0, 0, &seq_methods, 0, 0, 0, 0,
            0, 0, 0, Py_TPFLAGS_DEFAULT, NULL, 0, 0, 0, 0, (getiterfunc)shown_iter
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

            PyModule_AddObject(hsModule, "shown", PyObject_New(PyObject, &shown_type));
        }
    }

    namespace filter {

        static PyObject* filter_get(PyObject*)
        {
            return GetPyString(SniffWindow::window->ui->tb_filter->text().toUtf8().data());
        }

        static PyObject* filter_clear(PyObject*)
        {
            SniffWindow::window->ui->tb_filter->clear();
            SniffWindow::window->on_bt_filter_apply_clicked();
            Py_RETURN_NONE;
        }

        static PyObject* filter_set(PyObject*, PyObject* args)
        {
            const char* str = "";
            if (!PyArg_ParseTuple(args, "|z", &str))
            {
                return NULL;
            }
            SniffWindow::window->ui->tb_filter->setText(QString(str));
            SniffWindow::window->on_bt_filter_apply_clicked();
            Py_RETURN_NONE;
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
            "", sizeof(PyObject), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, Py_TPFLAGS_DEFAULT, NULL, 0, 0, 0, 0, 0, 0, hs_filter_methods
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
        emit SniffWindow::window->sig_clearCmd();
        Py_RETURN_NONE;
    }

    PyObject* open(PyObject*, PyObject* args)
    {
        const char* str;
        if (!PyArg_ParseTuple(args, "s", &str))
        {
            return NULL;
        }
        SniffWindow::window->runOfflineFile(str);
        Py_RETURN_NONE;
    }

    PyObject* stop(PyObject*)
    {
        emit SniffWindow::window->ui->actionStop->triggered();
        Py_RETURN_NONE;
    }

    PyObject* exit(PyObject*)
    {
        emit SniffWindow::window->ui->actionQuit->triggered();
        Py_RETURN_NONE;
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
        const char* str;
        if (!PyArg_ParseTuple(args, "s", &str))
        {
            return NULL;
        }
        emit SniffWindow::window->sig_appendToCmd(QStringLiteral("<font color=\"%1\">%2</font>").arg(self->color).arg(str).replace("\n", "<br/>"));
        Py_RETURN_NONE;
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
        "", sizeof(catch_obj), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, Py_TPFLAGS_DEFAULT, NULL, 0, 0, 0, 0, 0, 0, CatchOutErr_methods
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

QString PythonThread::getVersionString()
{
#ifdef Q_CC_MSVC
    return QStringLiteral("Python ").append(PY_VERSION);
#else
    return QStringLiteral("Python " PY_VERSION);
#endif
}

PythonThread::PythonThread()
{
    moveToThread(this);
    connect(this, SIGNAL(finished()), this, SLOT(stopPython()));
    connect(this, SIGNAL(sendCommand(QString)), this, SLOT(runCommand(QString)));
}

void PythonThread::runCommand(QString command)
{
    PyRun_String(command.toUtf8().constData(), Py_single_input, (PyObject*)pyGlobals, (PyObject*)pyGlobals);
    if (PyErr_Occurred())
    {
        PyErr_Print();
        PyErr_Clear();
    }
}

void PythonThread::stopPython()
{
    Py_Finalize();
}

void PythonThread::run()
{
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
    exec();
}

#endif
