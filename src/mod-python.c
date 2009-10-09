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

#ifndef WITH_PROTOCOL_P10
#error mod-python is only supported with p10 protocol enabled
#endif /* WITH_PROTOCOL_P10 */

#include <Python.h>
#include "chanserv.h"
#include "conf.h"
#include "modcmd.h"
#include "nickserv.h"
#include "opserv.h"
#include "saxdb.h"
#include "mail.h"
#include "timeq.h"
#include "compat.h"
#include "nickserv.h"

/* TODO notes
 *
 * - Implement most of proto-p10 irc_* commands for calling from scripts
 * - Implement functions to look up whois, channel, account, and reg-channel info for scripts
 * - Implement x3.conf settings for python variables like include path, etc.
 * - modpython.py calls for everything you can reg_ a handler for in x3
 * - Some kind of system for getting needed binds bound automagicaly to make it easier
 *   to run peoples' scripts and mod-python in general.
 * - An interface to reading/writing data to x3.db. Maybe generic, or attached to account or channel reg records?
 */

static const struct message_entry msgtab[] = {
    { "PYMSG_RELOAD_SUCCESS", "Reloaded Python scripts successfully." },
    { "PYMSG_RELOAD_FAILED", "Error reloading Python scripts." },
    { "PYMSG_RUN_UNKNOWN_EXCEPTION", "Error running python: unknown exception." },
    { "PYMSG_RUN_EXCEPTION", "Error running python: %s: %s." },
    { NULL, NULL } /* sentinel */
};

#define MODPYTHON_CONF_NAME "modules/python"

static
struct {
    char const* scripts_dir;
    char const* main_module;
} modpython_conf;

static struct log_type *PY_LOG;
const char *python_module_deps[] = { NULL };
static struct module *python_module;

PyObject *base_module = NULL; /* Base python handling library */
PyObject *handler_object = NULL; /* instance of handler class */


extern struct userNode *global, *chanserv, *opserv, *nickserv, *spamserv;

/*
Some hooks you can call from modpython.py to interact with the   
service. These emb_* functions are available as _svc.* in python. */

struct _tuple_dict_extra {
    PyObject* data;
    size_t* extra;
};

static void pyobj_release_tuple(PyObject* tuple, size_t n) {
    size_t i;

    if (tuple == NULL)
        return;

    for (i = 0; i < n; ++i)
        Py_XDECREF(PyTuple_GET_ITEM(tuple, i));

    Py_XDECREF(tuple);
}

static int _dict_iter_fill_tuple(char const* key, UNUSED_ARG(void* data), void* extra) {
    PyObject* tmp;
    struct _tuple_dict_extra* real_extra = (struct _tuple_dict_extra*)extra;

    if ((tmp = PyString_FromString(key)) == NULL)
        return 1;

    if (PyTuple_SetItem(real_extra->data, *(int*)real_extra->extra, tmp)) {
        Py_DECREF(tmp);
        return 1;
    }

    *real_extra->extra = *real_extra->extra + 1;
    return 0;
}

static PyObject*
pyobj_from_dict_t(dict_t d) {
    PyObject* retval;
    size_t n = 0;
    struct _tuple_dict_extra extra;

    if ((retval = PyTuple_New(dict_size(d))) == NULL)
        return NULL;

    extra.extra = &n;
    extra.data = retval;

    if (dict_foreach(d, _dict_iter_fill_tuple, (void*)&extra) != NULL) {
        pyobj_release_tuple(retval, n);
        return NULL;
    }

    return retval;
}

/* get a tuple with all users in it */
static PyObject*
emb_get_users(UNUSED_ARG(PyObject *self), PyObject *args) {
    if (!PyArg_ParseTuple(args, ""))
        return NULL;

    return pyobj_from_dict_t(clients);
}

/* get a tuple with all channels in it */
static PyObject*
emb_get_channels(UNUSED_ARG(PyObject* self), PyObject* args) {
    if (!PyArg_ParseTuple(args, ""))
        return NULL;

    return pyobj_from_dict_t(channels);
}

static PyObject*
emb_get_servers(UNUSED_ARG(PyObject* self), PyObject* args) {
    if (!PyArg_ParseTuple(args, ""))
        return NULL;

    return pyobj_from_dict_t(servers);
}

static PyObject*
emb_get_accounts(UNUSED_ARG(PyObject* self), PyObject* args) {
    if (!PyArg_ParseTuple(args, ""))
        return NULL;

    return pyobj_from_dict_t(nickserv_handle_dict);
}

static PyObject*
emb_dump(UNUSED_ARG(PyObject *self), PyObject *args)
{
    /* Dump a raw string into the socket 
        usage: _svc.dump(<P10 string>)
    */
    char *buf;
    int ret = 0;
    char linedup[MAXLEN];


    if(!PyArg_ParseTuple(args, "s:dump", &buf ))
        return NULL;

    safestrncpy(linedup, buf, sizeof(linedup));

    if(parse_line(linedup, 1)) {
        irc_raw(buf);
        ret = 1;
    } else {
        PyErr_SetString(PyExc_Exception, "invalid protocol message");
        return NULL;
    }

    return Py_BuildValue("i", ret);
}

static PyObject*
emb_send_target_privmsg(UNUSED_ARG(PyObject *self), PyObject *args)
{
    /* Send a privmsg 
        usage: _svc.send_target_privmsg(<servicenick_from>, <nick_to>, <message>)
    */
    int ret = 0;
    char *servicenick;
    char *channel;
    char *buf;

    struct service *service;


    if(!PyArg_ParseTuple(args, "sss:reply", &servicenick, &channel, &buf ))
        return NULL;

    if (buf == NULL || strlen(buf) == 0) {
        PyErr_SetString(PyExc_Exception, "invalid empty message");
        return NULL;
    }

    if(!(service = service_find(servicenick))) {
        PyErr_SetString(PyExc_Exception, "no such service nick");
        return NULL;
    }

    ret = send_target_message(5, channel, service->bot, "%s", buf);
    return Py_BuildValue("i", ret);
}

static PyObject*
emb_send_target_notice(UNUSED_ARG(PyObject *self), PyObject *args)
{
    /* send a notice
        usage: _svc.send_target_notice(<servicenick_from>, <nick_to>, <message>)
    */
    int ret = 0;
    char *servicenick;
    char *target;
    char *buf;

    struct service *service;

    if(!PyArg_ParseTuple(args, "sss:reply", &servicenick, &target, &buf ))
        return NULL;

    if (buf == NULL || strlen(buf) == 0) {
        PyErr_SetString(PyExc_Exception, "invalid empty message");
        return NULL;
    }

    if(!(service = service_find(servicenick))) {
        PyErr_SetString(PyExc_Exception, "no such service nick");
        return NULL;
    }

    ret = send_target_message(4, target, service->bot, "%s", buf);

    return Py_BuildValue("i", ret);
}

static PyObject*
pyobj_from_usernode(struct userNode* user) {
    unsigned int n;
    struct modeNode *mn;
    PyObject* retval = NULL;
    PyObject* pChanList = PyTuple_New(user->channels.used);

    if (pChanList == NULL)
        return NULL;

    for (n=0; n < user->channels.used; n++) {
        mn = user->channels.list[n];
        if (PyTuple_SetItem(pChanList, n, Py_BuildValue("s", mn->channel->name)))
            goto cleanup;
    }

    retval = Py_BuildValue("{"
            "s: s, " /* nick */
            "s: s, " /* ident */
            "s: s, " /* info */
            "s: s, " /* hostname */
            "s: s, " /* ip */
            "s: s, " /* fakehost */
            "s: s, " /* sethost */
            "s: s, " /* crypthost */
            "s: s, " /* cryptip */
            "s: s, " /* numeric */
            "s: i, " /* loc */
            "s: i, " /* no_notice */
            "s: s, " /* mark */
            "s: s, " /* version_reply */
            "s: s, " /* account */
            "s: O}", /* channels */
            "nick", user->nick,
            "ident", user->ident,
            "info", user->info,
            "hostname", user->hostname,
            "ip", irc_ntoa(&user->ip),
            "fakehost", user->fakehost,
            "sethost", user->sethost,
            "crypthost", user->crypthost,
            "cryptip", user->cryptip,
            "numeric", user->numeric,
            "loc", user->loc,
            "no_notice", user->no_notice,
            "mark", user->mark,
            "version_reply", user->version_reply,
            "account", user->handle_info ? user->handle_info->handle : NULL,
            "channels", pChanList);

    if (retval == NULL)
        goto cleanup;

    return retval;

cleanup:
    Py_XDECREF(retval);
    pyobj_release_tuple(pChanList, n);

    return NULL;
}

static PyObject*
emb_get_user(UNUSED_ARG(PyObject *self), PyObject *args)
{
    /* Get a python object containing everything x3 knows about a user, by nick.
        usage: _svc.get_user(<nick>)
    */
    char const* nick;
    struct userNode *user;

    if(!PyArg_ParseTuple(args, "s", &nick))
        return NULL;

    if(!(user = GetUserH(nick))) {
        PyErr_SetString(PyExc_Exception, "no such user");
        return NULL;
    }

    return pyobj_from_usernode(user);
}

static PyObject*
pyobj_from_server(struct server* srv) {
    size_t n, idx;
    PyObject* tmp = NULL;
    PyObject* retval = NULL;
    PyObject* users = PyTuple_New(srv->clients);

    if (users == NULL)
        return NULL;

    idx = 0;
    for (n = 0; n < srv->num_mask; ++n) {
        if (srv->users[n] == NULL)
            continue;

        tmp = PyString_FromString(srv->users[n]->nick);
        if (tmp == NULL)
            goto cleanup;

        if (PyTuple_SetItem(users, idx++, tmp))
            goto cleanup;
    }

    retval = Py_BuildValue("{"
            "s:s," /* name */
            "s:l," /* boot */
            "s:l," /* link_time */
            "s:s," /* description */
            "s:s," /* numeric */
            "s:I," /* num_mask */
            "s:I," /* hops */
            "s:I," /* clients */
            "s:I," /* max_clients */
            "s:I," /* burst */
            "s:I," /* self_burst */
            "s:s" /* uplink */
            "s:O" /* users */
            /* TODO: Children */
            "}",
            "name", srv->name,
            "boot", srv->boot,
            "link_time", srv->link_time,
            "description", srv->description,
            "numeric", srv->numeric,
            "num_mask", srv->num_mask,
            "hops", srv->hops,
            "clients", srv->clients,
            "max_clients", srv->max_clients,
            "burst", srv->burst,
            "self_burst", srv->self_burst,
            "uplink", srv->uplink ? srv->uplink->name : NULL,
            "users", users
            );

    if (retval == NULL)
        goto cleanup;

    return retval;

cleanup:
    Py_XDECREF(retval);
    pyobj_release_tuple(users, idx);

    return NULL;
}

static PyObject*
emb_get_server(UNUSED_ARG(PyObject* self), PyObject* args) {
    struct server* srv;
    char const* name;

    if (!PyArg_ParseTuple(args, "s", &name))
        return NULL;

    if (name == NULL || strlen(name) == 0) {
        PyErr_SetString(PyExc_Exception, "invalid server name");
        return NULL;
    }

    if ((srv = GetServerH(name)) == NULL) {
        PyErr_SetString(PyExc_Exception, "unknown server");
        return NULL;
    }

    return pyobj_from_server(srv);
}

static PyObject*
pyobj_from_modelist(struct modeList* mode) {
    size_t n;
    PyObject* tmp;
    PyObject* retval = PyTuple_New(mode->used);

    if (retval == NULL)
        return NULL;

    for (n = 0; n < mode->used; ++n) {
        struct modeNode* mn = mode->list[n];
        tmp = PyString_FromString(mn->user->nick);
        if (tmp == NULL) {
            pyobj_release_tuple(retval, n);
            return NULL;
        }

        if (PyTuple_SetItem(retval, n, tmp)) {
            pyobj_release_tuple(retval, n);
            return NULL;
        }
    }

    return retval;
}

static PyObject*
pyobj_from_banlist(struct banList* bans) {
    size_t n;
    struct banNode* bn;
    PyObject* tmp;
    PyObject* retval = PyTuple_New(bans->used);

    if (retval == NULL)
        return NULL;

    for (n = 0; n < bans->used; ++n) {
        bn = bans->list[n];

        tmp = Py_BuildValue("{s:s,s:s,s:l}",
                "ban", bn->ban, "who", bn->who, "set", bn->set);

        if (tmp == NULL || PyTuple_SetItem(retval, n, tmp)) {
            pyobj_release_tuple(retval, n);
            return NULL;
        }
     }

    return retval;
}

static PyObject*
pyobj_from_exemptlist(struct exemptList* exmp) {
    size_t n;
    struct exemptNode* en;
    PyObject* tmp;
    PyObject* retval = PyTuple_New(exmp->used);

    if (retval == NULL)
        return NULL;

    for (n = 0; n < exmp->used; ++n) {
        en = exmp->list[n];

        tmp = Py_BuildValue("{s:s,s:s,s:l}",
                "ban", en->exempt, "who", en->who, "set", en->set);

        if (tmp == NULL || PyTuple_SetItem(retval, n, tmp)) {
            pyobj_release_tuple(retval, n);
            return NULL;
        }
    }

    return retval;
}

static PyObject*
emb_get_channel(UNUSED_ARG(PyObject *self), PyObject *args)
{
    /* Returns a python dict object with all sorts of info about a channel.
          usage: _svc.get_channel(<name>)
    */
    char *name;
    struct chanNode *channel;
    PyObject *pChannelMembers = NULL;
    PyObject *pChannelBans = NULL;
    PyObject *pChannelExempts = NULL;
    PyObject *retval = NULL;


    if(!PyArg_ParseTuple(args, "s", &name))
        return NULL;

    if(!(channel = GetChannel(name))) {
        PyErr_SetString(PyExc_Exception, "unknown channel");
        return NULL;
    }

    /* build tuple of nicks in channel */
    pChannelMembers = pyobj_from_modelist(&channel->members);
    if (pChannelMembers == NULL)
        goto cleanup;

    /* build tuple of bans */
    pChannelBans = pyobj_from_banlist(&channel->banlist);
    if (pChannelBans == NULL)
        goto cleanup;

    /* build tuple of exempts */
    pChannelExempts = pyobj_from_exemptlist(&channel->exemptlist);
    if (pChannelExempts == NULL)
        goto cleanup;

    retval = Py_BuildValue("{s:s,s:s,s:s,s:i"
                         ",s:i,s:i,s:O,s:O,s:O}",

                         "name", channel->name,
                         "topic", channel->topic,
                         "topic_nick", channel->topic_nick,
                         "topic_time", channel->topic_time,

                         "timestamp", channel->timestamp,
                         "modes", channel->modes,
                         "members", pChannelMembers,
                         "bans", pChannelBans,
                         "exempts", pChannelExempts
            );
    if (retval == NULL)
        goto cleanup;

    return retval;

cleanup:
    Py_XDECREF(retval);
    pyobj_release_tuple(pChannelExempts, channel->exemptlist.used);
    pyobj_release_tuple(pChannelBans, channel->banlist.used);
    pyobj_release_tuple(pChannelMembers, channel->members.used);

    return NULL;
}

static PyObject*
emb_get_account(UNUSED_ARG(PyObject *self), PyObject *args)
{
    /* Returns a python dict object with all sorts of info about an account.
        usage: _svc.get_account(<account name>)
    */
    char *name;
    struct handle_info *hi;


    if(!PyArg_ParseTuple(args, "s", &name))
        return NULL;

    hi = get_handle_info(name);

    if(!hi) {
        PyErr_SetString(PyExc_Exception, "unknown account name");
        return NULL;
    }

    return Py_BuildValue("{s:s,s:i,s:s,s:s,s:s"
                         ",s:s,s:s}",
                            
                          "account", hi->handle,
                          "registered", hi->registered,
                          "last_seen", hi->lastseen,
                          "infoline",  hi->infoline ? hi->infoline : "",
                          "email", hi->email_addr ? hi->email_addr : "",
                          
                          "fakehost", hi->fakehost ? hi->fakehost : "",
                          "last_quit_host", hi->last_quit_host
                          
                          /* TODO: */
                          /* users online authed to this account */
                          /* cookies */
                          /* nicks (nickserv nets only?) */
                          /* masks */
                          /* ignores */
                          /* channels */
                           );
}

static PyObject*
emb_get_info(UNUSED_ARG(PyObject *self), UNUSED_ARG(PyObject *args))
{
    /* return some info about the general setup
     * of X3, such as what the chanserv's nickname
     * is.
     */


    return Py_BuildValue("{s:s,s:s,s:s,s:s,s:s}",
                          "chanserv", chanserv? chanserv->nick : "ChanServ",
                          "nickserv", nickserv?nickserv->nick : "NickServ",
                          "opserv", opserv?opserv->nick : "OpServ",
                          "global", global?global->nick : "Global",
                          "spamserv", spamserv?spamserv->nick : "SpamServ");
}

static PyObject*
emb_log_module(UNUSED_ARG(PyObject *self), PyObject *args)
{
    /* a gateway to standard X3 logging subsystem.
     * level is a value 0 to 9 as defined by the log_severity enum in log.h.
     *
     * for now, all logs go to the PY_LOG log. In the future this will change.
     */
    char *message;
    int ret = 0;
    int level;


    if(!PyArg_ParseTuple(args, "is", &level, &message))
        return NULL;

    log_module(PY_LOG, level, "%s", message);

    return Py_BuildValue("i", ret);
}

static PyObject*
emb_kill(UNUSED_ARG(PyObject* self), PyObject* args) {
    char const* from_nick, *target_nick, *message;
    struct userNode *target;
    struct service *service;

    if (!PyArg_ParseTuple(args, "sss", &from_nick, &target_nick, &message))
        return NULL;

    if(!(service = service_find(from_nick))) {
        PyErr_SetString(PyExc_Exception, "unknown service user specified as from user");
        return NULL;
    }

    if ((target = GetUserH(target_nick)) == NULL) {
        PyErr_SetString(PyExc_Exception, "unknown target user");
        return NULL;
    }

    irc_kill(service->bot, target, message);

    return Py_None;
}

struct py_timeq_extra {
    PyObject* func;
    PyObject* arg;
};

static 
void py_timeq_callback(void* data) {
    struct py_timeq_extra* extra = (struct py_timeq_extra*)data;

    PyObject* retval = PyObject_Call(extra->func, extra->arg, NULL);
    Py_XDECREF(retval);

    Py_DECREF(extra->func);
    Py_DECREF(extra->arg);
}

static PyObject*
emb_timeq_add(UNUSED_ARG(PyObject* self), PyObject* args) {
    time_t when;
    PyObject* func, *arg;
    struct py_timeq_extra* extra;

    if (!PyArg_ParseTuple(args, "lOO", &when, &func, &arg))
        return NULL;

    if (!PyFunction_Check(func)) {
        PyErr_SetString(PyExc_Exception, "first argument must be a function");
        return NULL;
    }

    if (!PyTuple_Check(arg)) {
        PyErr_SetString(PyExc_Exception, "second argument must be a tuple");
        return NULL;
    }

    extra = malloc(sizeof(struct py_timeq_extra));
    if (extra == NULL) {
        PyErr_SetString(PyExc_Exception, "out of memory");
        return NULL;
    }

    Py_INCREF(func);
    Py_INCREF(arg);

    extra->func = func;
    extra->arg = arg;

    timeq_add(when, py_timeq_callback, (void*)extra);

    return Py_None;
}

static PyMethodDef EmbMethods[] = {
    /* Communication methods */
    {"dump", emb_dump, METH_VARARGS, "Dump raw P10 line to server"},
    {"send_target_privmsg", emb_send_target_privmsg, METH_VARARGS, "Send a message to somewhere"},
    {"send_target_notice", emb_send_target_notice, METH_VARARGS, "Send a notice to somewhere"},
    {"log_module", emb_log_module, METH_VARARGS, "Log something using the X3 log subsystem"},
//TODO:    {"exec_cmd", emb_exec_cmd, METH_VARARGS, "execute x3 command provided"},
//          This should use environment from "python command" call to pass in, if available
    {"kill", emb_kill, METH_VARARGS, "Kill someone"},
//TODO:    {"shun"
//TODO:    {"unshun"
//TODO:    {"gline", emb_gline, METH_VARARGS, "gline a mask"},
//TODO:    {"ungline", emb_ungline, METH_VARARGS, "remove a gline"},
//TODO:    {"kick", emb_kick, METH_VARARGS, "kick someone from a channel"},
//TODO:    {"channel_mode", emb_channel_mode, METH_VARARGS, "set modes on a channel"},
//TODO:    {"user_mode", emb_user_mode, METH_VARARGS, "Have x3 set usermodes on one of its own nicks"},
//
//TODO:    {"get_config", emb_get_config, METH_VARARGS, "get x3.conf settings into a nested dict"},
//TODO:    {"config_set", emb_config_set, METH_VARARGS, "change a config setting 'on-the-fly'."},
//
    {"timeq_add", emb_timeq_add, METH_VARARGS, "add function to callback to the event system"},
//TODO:    {"timeq_del", emb_timeq_new, METH_VARARGS, "some kind of interface to the timed event system."},
    /* Information gathering methods */
    {"get_user", emb_get_user, METH_VARARGS, "Get details about a nickname"},
    {"get_users", emb_get_users, METH_VARARGS, "Get all connected users"},
    {"get_channel", emb_get_channel, METH_VARARGS, "Get details about a channel"},
    {"get_channels", emb_get_channels, METH_VARARGS, "Get all channels"},
    {"get_server", emb_get_server, METH_VARARGS, "Get details about a server"},
    {"get_servers", emb_get_servers, METH_VARARGS, "Get all server names"},
    {"get_account", emb_get_account, METH_VARARGS, "Get details about an account"},
    {"get_accounts", emb_get_accounts, METH_VARARGS, "Get all nickserv accounts"},
    {"get_info", emb_get_info, METH_VARARGS, "Get various misc info about x3"},
    /* null terminator */
    {NULL, NULL, 0, NULL}
};


/*
These functions set up the embedded environment for us to call out to
modpython.py class methods.  
 */

void python_log_module() {
    /* Attempt to convert python errors to x3 log system */
    PyObject *exc, *tb, *value, *tmp;
    char *str_exc = "NONE";
    char *str_value = "NONE";
    char *str_tb = "NONE";

    PyErr_Fetch(&exc, &value, &tb);

    if(exc) {
        if((tmp = PyObject_Str(exc)))
            str_exc = PyString_AsString(tmp);
    }
    if(value) {
        if((tmp = PyObject_Str(value)))
            str_value = PyString_AsString(tmp);
    }
    if(tb) {
        if((tmp = PyObject_Str(tb)))
            str_tb = PyString_AsString(tmp);
    }

    /* Now restore it so we can print it (just in case) 
     *   (should we do this only when running in debug mode?) */
    PyErr_Restore(exc, value, tb);
    PyErr_Print(); /* which of course, clears it again.. */

    log_module(PY_LOG, LOG_WARNING, "PYTHON error: %s, value: %s", str_exc, str_value);

    /* TODO: get the traceback using the traceback module via C api so we can add it to the X3 logs. See
     * http://mail.python.org/pipermail/python-list/2003-March/192226.html */
    // (this doesnt work, str_tb is just an object hashid) log_module(PY_LOG, LOG_INFO, "PYTHON error, traceback: %s", str_tb);
}


PyObject *python_build_handler_args(size_t argc, char *args[], PyObject *pIrcObj) {
    /* Sets up a python tuple with passed in arguments, prefixed by the Irc instance
       which handlers use to interact with C.
        argc = number of args
        args = array of args
        pIrcObj = instance of the irc class
    */
    size_t i = 0, n;
    PyObject *pArgs = NULL;

    pArgs = PyTuple_New(argc + 1);
    Py_INCREF(pIrcObj);
    PyTuple_SetItem(pArgs, i++, pIrcObj);

    if(args && argc) {
        PyObject *pValue;
        for(n = 0; n < argc; ++n) {
            pValue = PyString_FromString(args[n]);
            if(!pValue) {
                Py_DECREF(pArgs);
                log_module(PY_LOG, LOG_INFO, "Unable to convert '%s' to python string", args[n]);
                return NULL;
            }
            PyTuple_SetItem(pArgs, n+i, pValue);
        }
    }
    return pArgs;
}

PyObject *python_build_args(size_t argc, char *args[]) {
    /* Builds the passed in arguments into a python argument tuple.
         argc = number of args
         args = array of args
    */
    size_t i;
    PyObject *pArgs = NULL;

    if(args && argc) {
        pArgs = PyTuple_New(argc);
        PyObject *pValue;
        for(i = 0; i< argc; ++i) {
            pValue = PyString_FromString(args[i]);
            if(!pValue) {
                Py_DECREF(pArgs);
                log_module(PY_LOG, LOG_INFO, "Unable to convert '%s' to python string", args[i]);
                return NULL;
            }
            PyTuple_SetItem(pArgs, i, pValue);
        }
    }
    return pArgs;
}


PyObject *new_irc_object(char *command_service, char *command_caller, char *command_target) {
    /* Creates a new instance of the irc class (from modpython.py) which is initalized
       with current environment details like which service were talking to.
         command_service = which service we are talking to, or empty string if none
         command_caller = nick of user generating message, or empty string if none
         command_target = If were reacting to something on a channel, this will
                          be set to the name of the channel. Otherwise empty
    */
    PyObject *pIrcArgs = NULL;
    PyObject *pIrcClass;
    PyObject *pIrcObj;

    log_module(PY_LOG, LOG_INFO, "Attempting to instanciate irc class; %s %s %s", command_service, command_caller, command_target);
    pIrcClass = PyObject_GetAttrString(base_module, "irc");
    /* pIrcClass is a new reference */
    if(pIrcClass && PyCallable_Check(pIrcClass)) {
        //size_t i;
        char *ircargs[] = {command_service, command_caller, command_target};
        //PyObject *pValue;

        pIrcArgs = python_build_args(3, ircargs);
        pIrcObj = PyObject_CallObject(pIrcClass, pIrcArgs);
        if(!pIrcObj) {
            log_module(PY_LOG, LOG_ERROR, "IRC Class failed to load");
            python_log_module();
            //PyErr_Print();
        }
        if(pIrcArgs != NULL)  {
           Py_DECREF(pIrcArgs);
        }
        Py_DECREF(pIrcClass);
        return pIrcObj;
    }
    else {
        /* need to free pIrcClass here if it WAS found but was NOT callable? */
        log_module(PY_LOG, LOG_ERROR, "Unable to find irc class");
        return NULL;
    }
}

int python_call_handler(char *handler, char *args[], size_t argc, char *command_service, char *command_caller, char *command_target) {
    /*  This is how we talk to modpython.c.  First a new instance of the irc class is created using these
        arguments to setup the current environment. Then the named method of the handler object is called
        with the givin arguments.
     */
    PyObject *pIrcObj;
    PyObject *pArgs;
    PyObject *pMethod;
    PyObject *pValue;

    log_module(PY_LOG, LOG_INFO, "attempting to call handler %s.", handler);
    if(base_module != NULL && handler_object != NULL) {
        pIrcObj = new_irc_object(command_service, command_caller, command_target);
        if(!pIrcObj) {
            log_module(PY_LOG, LOG_INFO, "Can't get irc object. Bailing.");
            return 0;
        }

        pArgs = python_build_handler_args(argc, args, pIrcObj);
        pMethod = PyObject_GetAttrString(handler_object, handler);
        if(pMethod && PyCallable_Check(pMethod)) {
            /* Call the method, with the arguments */
            pValue = PyObject_CallObject(pMethod, pArgs);
            if(pArgs) {
                Py_DECREF(pArgs);
            }
            if(pValue != NULL) {
                int ret;
                ret = PyInt_AsLong(pValue);
                if(ret == -1 && PyErr_Occurred()) {
                    //PyErr_Print();
                    log_module(PY_LOG, LOG_INFO, "error converting return value of handler %s to type long. ", handler);
                    python_log_module();
                    ret = 0;
                }
                log_module(PY_LOG, LOG_INFO, "handler %s was run successfully, returned %d.", handler, ret);
                Py_DECREF(pValue);
                Py_DECREF(pIrcObj);
                Py_DECREF(pMethod);
                return ret;
            }
            else {
                /* TODO: instead of print errors, get them as strings
                 * and deal with them with normal x3 log system. */
                log_module(PY_LOG, LOG_WARNING, "call to handler %s failed", handler);
                //PyErr_Print();
                python_log_module();
                Py_DECREF(pIrcObj);
                Py_DECREF(pMethod);
                return 0;
            }
        }
        else { /* couldn't find handler methed */
            Py_DECREF(pArgs);
            /* Free pMethod if it was found but not callable? */
            log_module(PY_LOG, LOG_ERROR, "Cannot find handler %s.", handler);
            return 0;

        }
    } 
    else { /* No base module.. no python? */
        log_module(PY_LOG, LOG_INFO, "Cannot handle %s, Python is not initialized.", handler);
        return 0;
    }
}

PyObject *python_new_handler_object() {
    /* Create a new instance of the handler class. 
       This is called during python initilization (or reload)
       and the result is saved and re-used.
    */
    PyObject *pHandlerClass, *pHandlerObj;

    log_module(PY_LOG, LOG_INFO, "Attempting to instanciate python class handler");
    pHandlerClass = PyObject_GetAttrString(base_module, "handler");
    /* Class is a new reference */
    if(pHandlerClass && PyCallable_Check(pHandlerClass)) {
        /*PyObject *pValue; */

        pHandlerObj = PyObject_CallObject(pHandlerClass, NULL);
        if(pHandlerObj != NULL) {
            log_module(PY_LOG, LOG_INFO, "Created new python handler object.");
            return pHandlerObj;
        }
        else {
            log_module(PY_LOG, LOG_ERROR, "Unable to instanciate handler object");
            //PyErr_Print();
            python_log_module();
            return NULL;
        }
    }
    else {
        log_module(PY_LOG, LOG_ERROR, "Unable to find handler class");
        //PyErr_Print();
        python_log_module();
        if(pHandlerClass) {
            Py_DECREF(pHandlerClass);
        }
        return NULL;
    }
}

/* ------------------------------------------------------------------------------- *
    Some gateway functions to convert x3 callbacks into modpython.py callbacks.
    Mostly we just build relevant args and call the proper handler method

   debate: do we just register these and check them in python
   for every one (slow?) or actually work out if a plugin needs
   it first? We will start by doing it every time.
 */
static int
python_handle_join(struct modeNode *mNode)
{
    /* callback for handle_join events. 
    */
    struct userNode *user = mNode->user;
    struct chanNode *channel = mNode->channel;


    log_module(PY_LOG, LOG_INFO, "python module handle_join");
    if(!channel||!user) {
        log_module(PY_LOG, LOG_WARNING, "Python code got join without channel or user!");
        return 0;
    }
    else {
        char *args[] = {channel->name, user->nick};
        return python_call_handler("join", args, 2, "", "", "");
    }
}

static int
python_handle_server_link(struct server *server)
{
    log_module(PY_LOG, LOG_INFO, "python module handle_server_link");
    if(!server) {
        log_module(PY_LOG, LOG_WARNING, "Python code got server link without server!");
        return 0;
    }
    else {
        char *args[] = {server->name, server->description};
        return python_call_handler("server_link", args, 2, "", "", "");
    }
}

static int
python_handle_new_user(struct userNode *user)
{
    log_module(PY_LOG, LOG_INFO, "Python module handle_new_user");
    if(!user) {
        log_module(PY_LOG, LOG_WARNING, "Python code got new_user without the user");
        return 0;
    }
    else {
        char *args[] = {user->nick, user->ident, user->hostname, user->info};
        return python_call_handler("new_user", args, 4, "", "", "");
    }
}

static void
python_handle_nick_change(struct userNode *user, const char *old_nick)
{
    log_module(PY_LOG, LOG_INFO, "Python module handle_nick_change");
    if(!user) {
        log_module(PY_LOG, LOG_WARNING, "Python code got nick_change without the user!");
    }
    else {
        char *args[] = {user->nick, (char *)old_nick};
        python_call_handler("nick_change", args, 2, "", "", "");
    }
}

/* ----------------------------------------------------------------------------- */
   

int python_load() {
    /* Init the python engine and do init work on modpython.py
       This is called during x3 startup, and on a python reload
    */
    PyObject *pName;
    char* buffer;
    char* env = getenv("PYTHONPATH");

    if (env)
        env = strdup(env);

    if (!env)
        setenv("PYTHONPATH", modpython_conf.scripts_dir, 1);
    else if (!strstr(env, modpython_conf.scripts_dir)) {
        buffer = (char*)malloc(strlen(env) + strlen(modpython_conf.scripts_dir) + 2);
        sprintf(buffer, "%s:%s", modpython_conf.scripts_dir, env);
        setenv("PYTHONPATH", buffer, 1);
        free(buffer);
        free(env);
    }

    Py_Initialize();
    Py_InitModule("_svc", EmbMethods);
    pName = PyString_FromString(modpython_conf.main_module);
    base_module = PyImport_Import(pName);
    Py_DECREF(pName);

    Py_XDECREF(handler_object);
    handler_object = NULL;

    if(base_module != NULL) {
        handler_object = python_new_handler_object();
        if(handler_object) {
            python_call_handler("init", NULL, 0, "", "", "");
            return 1;
        }
        else {
            /* error handler class not found */
            log_module(PY_LOG, LOG_WARNING, "Failed to create handler object");
            return 0;
        }
    }
    else {
        //PyErr_Print();
        python_log_module();
        log_module(PY_LOG, LOG_WARNING, "Failed to load modpython.py");
        return 0;
    }
    return 0;
}

int
python_finalize(void) {
    /* Called after X3 is fully up and running. 
       Code can be put here that needs to run to init things, but
       which is sensitive to everything else in x3 being up and ready
       to go.
     */

    PyRun_SimpleString("print 'Hello, World of Python!'");
    log_module(PY_LOG, LOG_INFO, "python module finalize");

    return 1;
}

static void
python_cleanup(void) {
    /* Called on shutdown of the python module  (or before reloading)
    */

    log_module(PY_LOG, LOG_INFO, "python module cleanup");
    if (PyErr_Occurred())
        PyErr_Clear();
    Py_Finalize(); /* Shut down python enterpreter */
}

/* ---------------------------------------------------------------------------------- *
   Python module command handlers. 
*/
static MODCMD_FUNC(cmd_reload) {
    /* reload the python system completely 
    */
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

static char* format_python_error(int space_nls) {
    PyObject* extype = NULL, *exvalue = NULL, *extraceback = NULL;
    PyObject* pextypestr = NULL, *pexvaluestr = NULL;
    char* extypestr = NULL, *exvaluestr = NULL;
    size_t retvallen = 0;
    char* retval = NULL, *tmp;

    PyErr_Fetch(&extype, &exvalue, &extraceback);
    if (!extype)
        goto cleanup;

    pextypestr = PyObject_Str(extype);
    if (!pextypestr)
        goto cleanup;
    extypestr = PyString_AsString(pextypestr);
    if (!extypestr)
        goto cleanup;

    pexvaluestr = PyObject_Str(exvalue);
    if (pexvaluestr)
        exvaluestr = PyString_AsString(pexvaluestr);

    retvallen = strlen(extypestr) + (exvaluestr ? strlen(exvaluestr) + 2 : 0) + 1;
    retval = (char*)malloc(retvallen);
    if (exvaluestr)
        snprintf(retval, retvallen, "%s: %s", extypestr, exvaluestr);
    else
        strncpy(retval, extypestr, retvallen);

    if (space_nls) {
        tmp = retval;
        while (*tmp) {
            if (*tmp == '\n')
                *tmp = ' ';
            ++tmp;
        }
    }

cleanup:
    if (PyErr_Occurred())
        PyErr_Clear(); /* ignore errors caused by formatting */
    Py_XDECREF(extype);
    Py_XDECREF(exvalue);
    Py_XDECREF(extraceback);
    Py_XDECREF(pextypestr);
    Py_XDECREF(pexvaluestr);

    if (retval)
        return retval;

    return strdup("unknown exception");
}

static MODCMD_FUNC(cmd_run) {
    /* this method allows running arbitrary python commands.
     * use with care.
     */
    char* msg;
    PyObject* py_main_module;
    PyObject* py_globals;
    PyObject* py_locals;
    PyObject* py_retval;
    PyObject* extype, *exvalue, *extraceback;
    PyObject* exvaluestr = NULL;
    char* exmsg = NULL, *exmsgptr;

    py_main_module = PyImport_AddModule("__main__");
    py_globals = py_locals = PyModule_GetDict(py_main_module);

    msg = unsplit_string(argv + 1, argc - 1, NULL);

    py_retval = PyRun_String(msg, Py_file_input, py_globals, py_locals);
    if (py_retval == NULL) {
        PyErr_Fetch(&extype, &exvalue, &extraceback);
        if (exvalue != NULL) {
            exvaluestr = PyObject_Str(exvalue);
            exmsg = strdup(PyString_AS_STRING(exvaluestr));
            exmsgptr = exmsg;
            while (exmsgptr && *exmsgptr) {
                if (*exmsgptr == '\n' || *exmsgptr == '\r' || *exmsgptr == '\t')
                    *exmsgptr = ' ';
                exmsgptr++;
            }
        }
        if (extype != NULL && exvalue != NULL && PyType_Check(extype)) {
            reply("PYMSG_RUN_EXCEPTION", ((PyTypeObject*)extype)->tp_name, exmsg);
        } else
            reply("PYMSG_RUN_UNKNOWN_EXCEPTION");

        if (extype != NULL)
            Py_DECREF(extype);
        if (exvalue != NULL)
            Py_DECREF(exvalue);
        if (extraceback != NULL)
            Py_DECREF(extraceback);
        if (exvaluestr != NULL)
            Py_DECREF(exvaluestr);
        if (exmsg)
            free(exmsg);
    } else {
        Py_DECREF(py_retval);
    }

    return 1;
}

#define numstrargs(X)   sizeof(X) / sizeof(*X)
static MODCMD_FUNC(cmd_command) {
    char *plugin = argv[1];
    char *command = argv[2];
    char *msg; /* args */
    if(argc > 3) {
       msg = unsplit_string(argv + 3, argc - 3, NULL);
    }
    else {
        msg = "";
    }
    char *args[] = {plugin, command, msg};
    python_call_handler("cmd_command", args, numstrargs(args), cmd->parent->bot->nick, user?user->nick:"", channel?channel->name:"");
    return 1;
}

static void modpython_conf_read(void) {
    dict_t conf_node;
    char const* str;

    if (!(conf_node = conf_get_data(MODPYTHON_CONF_NAME, RECDB_OBJECT))) {
        log_module(PY_LOG, LOG_ERROR, "config node '%s' is missing or has wrong type", MODPYTHON_CONF_NAME);
        return;
    }

    str = database_get_data(conf_node, "scripts_dir", RECDB_QSTRING);
    modpython_conf.scripts_dir = str ? str : "./";

    str = database_get_data(conf_node, "main_module", RECDB_QSTRING);
    modpython_conf.main_module = str ? str : "modpython";
}

int python_init(void) {
    /* X3 calls this function on init of the module during startup. We use it to
       do all our setup tasks and bindings 
    */

    PY_LOG = log_register_type("Python", "file:python.log");
    python_module = module_register("python", PY_LOG, "mod-python.help", NULL);
    conf_register_reload(modpython_conf_read);

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
    modcmd_register(python_module, "run",  cmd_run,  2,  MODCMD_REQUIRE_AUTHED, "flags", "+oper", NULL);
    modcmd_register(python_module, "command", cmd_command, 3, MODCMD_REQUIRE_STAFF, NULL);

//  Please help us by implementing any of the callbacks listed as TODO below. They already exist
//  in x3, they just need handle_ bridges implemented. (see python_handle_join for an example)
    reg_server_link_func(python_handle_server_link);
    reg_new_user_func(python_handle_new_user);
    reg_nick_change_func(python_handle_nick_change);
//TODO:    reg_del_user_func(python_handle_del_user);
//TODO:    reg_account_func(python_handle_account); /* stamping of account name to the ircd */
//TODO:    reg_handle_rename_func(python_handle_handle_rename); /* handle used to ALSO mean account name */
//TODO:    reg_failpw_func(python_handle_failpw);
//TODO:    reg_allowauth_func(python_handle_allowauth);
//TODO:    reg_handle_merge_func(python_handle_merge);
//
//TODO:    reg_oper_func(python_handle_oper);
//TODO:    reg_new_channel_func(python_handle_new_channel);
    reg_join_func(python_handle_join);
//TODO:    reg_del_channel_func(python_handle_del_channel);
//TODO:    reg_part_func(python_handle_part);
//TODO:    reg_kick_func(python_handle_kick);
//TODO:    reg_topic_func(python_handle_topic);
//TODO:    reg_channel_mode_func(python_handle_channel_mode);

//TODO:    reg_privmsg_func(python_handle_privmsg);
//TODO:    reg_notice_func
//TODO:    reg_svccmd_unbind_func(python_handle_svccmd_unbind);
//TODO:    reg_chanmsg_func(python_handle_chanmsg);
//TODO:    reg_allchanmsg_func
//TODO:    reg_user_mode_func

    reg_exit_func(python_cleanup);

    python_load();
    return 1;
}

#endif /* WITH_PYTHON */
