/* mod-python.c - Script module for x3
 * Copyright 2003-2004 Martijn Smit and srvx Development Team
 * Copyright 2005-2006 X3 Development Team
 *
 * This file is part of x3.
 *
 * x3 is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with srvx; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.
 */

#include "config.h"
#ifdef WITH_PYTHON /* just disable this file if python doesnt exist */


#include "Python.h"
#include "chanserv.h"
#include "conf.h"
#include "modcmd.h"
#include "nickserv.h"
#include "opserv.h"
#include "saxdb.h"
#include "sendmail.h"
#include "timeq.h"

/* TODO notes
 *
 * - Impliment most of proto-p10 irc_* commands for calling from scripts
 * - Impliment functions to look up whois, channel, account, and reg-channel info for scripts
 * - Impliment x3.conf settings for python variables like include path, etc.
 * - kod-python.py calls for everything you can reg_ a handler for in x3
 * - Some kind of system for getting needed binds bound automagicaly to make it easier
 *   to run peoples scripts and mod-python in general.
 */

static const struct message_entry msgtab[] = {
    { "PYMSG_RELOAD_SUCCESS", "Reloaded Python scripts successfully." },
    { "PYMSG_RELOAD_FAILED", "Error reloading Python scripts." },
    { NULL, NULL } /* sentenal */
};

static struct log_type *PY_LOG;
const char *python_module_deps[] = { NULL };
static struct module *python_module;

PyObject *base_module = NULL; /* Base python handling library */

static PyObject*
emb_dump(PyObject *self, PyObject *args)
{
    char *buf;
    int ret = 0;
    char linedup[MAXLEN];

    if(!PyArg_ParseTuple(args, "s:dump", &buf ))
        return NULL;
    safestrncpy(linedup, buf, sizeof(linedup));
    if(parse_line(linedup, 1)) {
        irc_raw(buf);
        ret = 1;
    }
    return Py_BuildValue("i", ret);
}

static PyObject*
emb_send_target_privmsg(PyObject *self, PyObject *args)
{
    int ret = 0;
    char *servicenick;
    char *channel;
    char *buf;

    struct service *service;

    if(!PyArg_ParseTuple(args, "sss:reply", &servicenick, &channel, &buf ))
        return NULL;
    if(!(service = service_find(servicenick))) {
        /* TODO: generate python exception here */
        return 0;
    }
    send_target_message(5, channel, service->bot, "%s", buf);
    return Py_BuildValue("i", ret);
}

static PyMethodDef EmbMethods[] = {
    {"dump", emb_dump, METH_VARARGS, "Dump raw P10 line to server"},
    {"send_target_privmsg", emb_send_target_privmsg, METH_VARARGS, "Send a message to somewhere"},
    {NULL, NULL, 0, NULL}
};


int python_call_func(char *function, char *args[], size_t argc) {
    /* TODO: get arguments, pass through to python function */
    PyObject *pFunc, *pValue;
    PyObject *pArgs = NULL;
    if(base_module != NULL) {
        log_module(PY_LOG, LOG_INFO, "Attempting to run python function %s", function);
        pFunc = PyObject_GetAttrString(base_module, function);
        /* pFunc is a new reference */
        if(pFunc && PyCallable_Check(pFunc)) {
            size_t i;
            if(args && argc) {
                pArgs = PyTuple_New(argc);
                for(i = 0; i< argc; ++i) {
                    pValue = PyString_FromString(args[i]);
                    if(!pValue) {
                        Py_DECREF(pArgs);
                        Py_DECREF(pFunc);
                        log_module(PY_LOG, LOG_INFO, "Unable to convert '%s' to python string", args[i]);
                        return 0;
                    }
                    PyTuple_SetItem(pArgs, i, pValue);
                }
            }
            pValue = PyObject_CallObject(pFunc, pArgs);
            if(pArgs != NULL)  {
               Py_DECREF(pArgs);
            }
            if(pValue != NULL) {
                int ret;
                ret = PyInt_AsLong(pValue);
                if(ret == -1 && PyErr_Occurred()) {
                    PyErr_Print();
                    log_module(PY_LOG, LOG_INFO, "error converting return value of %s to type long. ", function);
                    ret = 0;
                }
                log_module(PY_LOG, LOG_INFO, "%s was run successfully, returned %d.", function, ret);
                /* TODO: convert pValue to c int, return it below */
                Py_DECREF(pValue);
                return ret;
            }
            else {
                Py_DECREF(pFunc);
                /* TODO: instead of print errors, get them as strings
                 * and deal with them with normal x3 log system. */
                PyErr_Print();
                log_module(PY_LOG, LOG_WARNING, "call to %s failed", function);
                return 0;
            }
        }
        else {
            if(PyErr_Occurred())
                PyErr_Print();
            log_module(PY_LOG, LOG_WARNING, "function %s not found or uncallable", function);
            return 0;
        }
    } 
    else {
        return 0;
    }
}


static int
python_handle_join(struct modeNode *mNode)
{
    struct userNode *user = mNode->user;
    struct chanNode *channel = mNode->channel;


    log_module(PY_LOG, LOG_INFO, "python module handle_join");
    if(!channel||!user) {
        return 0;
    }
    else {
        char *args[] = {channel->name, user->nick};
        return python_call_func("handle_join", args, 2);
    }
}

int python_load() {
    PyObject *pName;

    setenv("PYTHONPATH", "/home/rubin/afternet/services/x3/x3-run/", 1);
    Py_Initialize();
    Py_InitModule("svc", EmbMethods);
    PyRun_SimpleString("import svc");
    /* TODO: get "mod-python" from x3.conf */
    pName = PyString_FromString("mod-python");
    base_module = PyImport_Import(pName);
    Py_DECREF(pName);
    if(base_module != NULL) {
        python_call_func("handle_init", NULL, 0);
        return 1;
    }
    else {
        PyErr_Print();
        log_module(PY_LOG, LOG_WARNING, "Failed to load mod-python.py");
        return 0;
    }
}

/* Called after X3 is fully up and running */
int
python_finalize(void) {

    PyRun_SimpleString("print 'Hello, World of Python!'");
    log_module(PY_LOG, LOG_INFO, "python module finalize");

    return 1;
}

/* Called on shutdown of the module */
static void
python_cleanup(void)
{
    log_module(PY_LOG, LOG_INFO, "python module cleanup");
    Py_Finalize(); /* Shut down python enterpriter */
    return;
}

static MODCMD_FUNC(cmd_reload) {
    log_module(PY_LOG, LOG_INFO, "Shutting python down");
    python_cleanup();
    log_module(PY_LOG, LOG_INFO, "Loading python stuff");
    if(python_load()) {
         reply("PYMSG_RELOAD_SUCCESS");
    }
    else {
        reply("PYMSG_RELOAD_FAILED");
    }
    return 1;
}

static MODCMD_FUNC(cmd_python) {
    
    char *msg;
    msg = unsplit_string(argv + 1, argc - 1, NULL);
    PyRun_SimpleString(msg);
    return 1;
}

/* Called on init of the module during startup */
int python_init(void) {

    PY_LOG = log_register_type("Python", "file:python.log");
    python_module = module_register("python", PY_LOG, "mod-python.help", NULL);
    log_module(PY_LOG, LOG_INFO, "python module init");
    message_register_table(msgtab);

/*
    reg_auth_func(python_check_messages);
    reg_handle_rename_func(python_rename_account);
    reg_unreg_func(python_unreg_account);
    conf_register_reload(python_conf_read);
    saxdb_register("python", python_saxdb_read, python_saxdb_write);
    modcmd_register(python_module, "send",    cmd_send,    3, MODCMD_REQUIRE_AUTHED, NULL);
*/
    modcmd_register(python_module, "reload",  cmd_reload,  1,  MODCMD_REQUIRE_AUTHED, "flags", "+oper", NULL);
    modcmd_register(python_module, "python",  cmd_python,  2,  MODCMD_REQUIRE_AUTHED, "flags", "+oper", NULL);
    reg_join_func(python_handle_join);
    reg_exit_func(python_cleanup);

    python_load();
    return 1;
}

#endif /* WITH_PYTHON */
