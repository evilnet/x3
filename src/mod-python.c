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


static const struct message_entry msgtab[] = {
    { "PYMSG_RELOAD_SUCCESS", "Reloaded Python scripts successfully." },
    { "PYMSG_RELOAD_FAILED", "Error reloading Python scripts." },
    { NULL, NULL } /* sentenal */
};

static struct log_type *PY_LOG;
const char *python_module_deps[] = { NULL };
static struct module *python_module;

PyObject *base_module = NULL; /* Base python handling library */

int python_call_func(char *function, ...) {
    /* TODO: get arguments, pass through to python function */
    PyObject *pFunc, *pValue;
    if(base_module != NULL) {
        log_module(PY_LOG, LOG_INFO, "%s returned successfully", function);
	pFunc = PyObject_GetAttrString(base_module, function);
	/* pFunc is a new reference */
	if(pFunc && PyCallable_Check(pFunc)) {
	    pValue = PyObject_CallObject(pFunc, NULL);
	    if(pValue != NULL) {
		log_module(PY_LOG, LOG_INFO, "%s returned successfully", function);
		Py_DECREF(pValue);
		return 1;
	    }
	    else {
		Py_DECREF(pFunc);
		Py_DECREF(base_module);
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
    python_call_func("handle_join");
    PyRun_SimpleString("print 'Someone joined a channel somewhere'");
    return 0;
}

int python_load() {
    PyObject *pName;

    setenv("PYTHONPATH", "/home/rubin/afternet/services/x3/x3-run/", 1);
    Py_Initialize();
    /* TODO: get "mod-python" from x3.conf */
    pName = PyString_FromString("mod-python");
    base_module = PyImport_Import(pName);
    Py_DECREF(pName);
    if(base_module != NULL) {
	return python_call_func("handle_init");
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
    reg_join_func(python_handle_join);
    reg_exit_func(python_cleanup);

    python_load();
    return 1;
}

#endif /* WITH_PYTHON */
