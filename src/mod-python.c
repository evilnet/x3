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
#include "compat.h"

/* TODO notes
 *
 * - Impliment most of proto-p10 irc_* commands for calling from scripts
 * - Impliment functions to look up whois, channel, account, and reg-channel info for scripts
 * - Impliment x3.conf settings for python variables like include path, etc.
 * - modpython.py calls for everything you can reg_ a handler for in x3
 * - Some kind of system for getting needed binds bound automagicaly to make it easier
 *   to run peoples scripts and mod-python in general.
 * - An interface to reading/writing data to x3.db. Maybe generic, or attached to account or channel reg records?
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
PyObject *handler_object = NULL; /* instanciation of handler class */


extern struct userNode *global, *chanserv, *opserv, *nickserv, *spamserv;

/* ---------------------------------------------------------------------- * 
    Some hooks you can call from modpython.py to interact with the   
    service, and IRC.  These emb_* functions are available as svc.*
    in python.
 */

static PyObject*
emb_dump(UNUSED_ARG(PyObject *self), PyObject *args)
{
    /* Dump a raw string into the socket 
        usage: svc.dump(<P10 string>)
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
    }
    return Py_BuildValue("i", ret);
}

static PyObject*
emb_send_target_privmsg(UNUSED_ARG(PyObject *self), PyObject *args)
{
    /* Send a privmsg 
        usage: svc.send_target_privmsg(<servicenick_from>, <nick_to>, <message>)
    */
    int ret = 0;
    char *servicenick;
    char *channel;
    char *buf;

    struct service *service;


    if(!PyArg_ParseTuple(args, "sss:reply", &servicenick, &channel, &buf ))
        return NULL;
    if(!(service = service_find(servicenick))) {
        /* TODO: generate python exception here */
        return NULL;
    }
    send_target_message(5, channel, service->bot, "%s", buf);
    return Py_BuildValue("i", ret);
}

static PyObject*
emb_send_target_notice(UNUSED_ARG(PyObject *self), PyObject *args)
{
    /* send a notice
        usage: svc.send_target_notice(<servicenick_from>, <nick_to>, <message>)
    */
    int ret = 0;
    char *servicenick;
    char *target;
    char *buf;

    struct service *service;


    if(!PyArg_ParseTuple(args, "sss:reply", &servicenick, &target, &buf ))
        return NULL;
    if(!(service = service_find(servicenick))) {
        /* TODO: generate python exception here */
        return NULL;
    }
    send_target_message(4, target, service->bot, "%s", buf);
    return Py_BuildValue("i", ret);
}

static PyObject*
emb_get_user(UNUSED_ARG(PyObject *self), PyObject *args)
{
    /* Get a python object containing everything x3 knows about a user, by nick.
        usage: svc.get_user(<nick>)
    */
    char *nick;
    struct userNode *user;
    struct modeNode *mn;
    unsigned int n;
    PyObject* pChanList;


    if(!PyArg_ParseTuple(args, "s", &nick))
        return NULL;
    if(!(user = GetUserH(nick))) {
        /* TODO: generate python exception here */
        return NULL;
    }
    pChanList = PyTuple_New(user->channels.used);
    for(n=0;n<user->channels.used;n++) {
        mn = user->channels.list[n];
        PyTuple_SetItem(pChanList, n, Py_BuildValue("s", mn->channel->name));
    }
    return Py_BuildValue("{s:s,s:s,s:s,s:s,s:s"   /* format strings. s=string, i=int */
                         ",s:s,s:s,s:s,s:s,s:s"   /* (format is key:value)  O=object */
                         ",s:i,s:i,s:s,s:s,s:s"   /* blocks of 5 for readability     */
                         "s:O}", 

                         "nick", user->nick,
                         "ident", user->ident,
                         "info", user->info,
                         "hostname", user->hostname,
                         "ip", irc_ntoa(&user->ip),

                         "fakehost", user->fakehost,
                         "sethost", user->sethost,
                         "crypthost", user->crypthost,
                         "cryptip", user->cryptip,
                         "numeric", user->numeric, /* TODO: only ifdef WITH_PROTOCOL_P10 */

                         "loc", user->loc,
                         "no_notice", user->no_notice,
                         "mark", user->mark,
                         "version_reply", user->version_reply,
                         "account", user->handle_info?user->handle_info->handle:NULL,
                         "channels", pChanList);
}

static PyObject*
emb_get_channel(UNUSED_ARG(PyObject *self), PyObject *args)
{
    /* Returns a python dict object with all sorts of info about a channel.
          usage: svc.get_channel(<name>)
    */
    char *name;
    struct chanNode *channel;
    unsigned int n;
    PyObject *pChannelMembers;
    PyObject *pChannelBans;
    PyObject *pChannelExempts;


    if(!PyArg_ParseTuple(args, "s", &name))
        return NULL;
    if(!(channel = GetChannel(name))) {
        /* TODO: generate py exception here */
        return NULL;
    }

    /* build tuple of nicks in channel */
    pChannelMembers = PyTuple_New(channel->members.used);
    for(n=0;n < channel->members.used;n++) {
        struct modeNode *mn = channel->members.list[n];
        PyTuple_SetItem(pChannelMembers, n, Py_BuildValue("s", mn->user->nick));
    }

    /* build tuple of bans */
    pChannelBans = PyTuple_New(channel->banlist.used);
    for(n=0; n < channel->banlist.used;n++) {
        struct banNode *bn = channel->banlist.list[n];
        PyTuple_SetItem(pChannelBans, n, 
                        Py_BuildValue("{s:s,s:s,s:i}",
                            "ban", bn->ban,
                            "who", bn->who,
                            "set", bn->set)
                );
    }

    /* build tuple of exempts */
    pChannelExempts = PyTuple_New(channel->exemptlist.used);
    for(n=0; n < channel->exemptlist.used;n++) {
        struct exemptNode *en = channel->exemptlist.list[n];
        PyTuple_SetItem(pChannelExempts, n, 
                        Py_BuildValue("{s:s,s:s,s:i}",
                            "ban", en->exempt,
                            "who", en->who,
                            "set", en->set)
                );
    }

    return Py_BuildValue("{s:s,s:s,s:s,s:i"
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
}

static PyObject*
emb_get_account(UNUSED_ARG(PyObject *self), PyObject *args)
{
    /* Returns a python dict object with all sorts of info about an account.
        usage: svc.get_account(<account name>)
    */
    char *name;
    struct handle_info *hi;


    if(!PyArg_ParseTuple(args, "s", &name))
        return NULL;

    hi = get_handle_info(name);
    if(!hi) {
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
     * LOG_INFO is 3, LOG_WARNING is 6, LOG_ERROR is 7.
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

static PyMethodDef EmbMethods[] = {
    /* Communication methods */
    {"dump", emb_dump, METH_VARARGS, "Dump raw P10 line to server"},
    {"send_target_privmsg", emb_send_target_privmsg, METH_VARARGS, "Send a message to somewhere"},
    {"send_target_notice", emb_send_target_notice, METH_VARARGS, "Send a notice to somewhere"},
    {"log_module", emb_log_module, METH_VARARGS, "Log something using the X3 log subsystem"},
//TODO:    {"exec_cmd", emb_exec_cmd, METH_VARARGS, "execute x3 command provided"},
//          This should use environment from "python command" call to pass in, if available
//TODO:    {"kill"
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
//TODO:    {"timeq_add", emb_timeq_new, METH_VARARGS, "some kind of interface to the timed event system."},
//TODO:    {"timeq_del", emb_timeq_new, METH_VARARGS, "some kind of interface to the timed event system."},
    /* Information gathering methods */
    {"get_user", emb_get_user, METH_VARARGS, "Get details about a nickname"},
    {"get_channel", emb_get_channel, METH_VARARGS, "Get details about a channel"},
    {"get_account", emb_get_account, METH_VARARGS, "Get details about an account"},
    {"get_info", emb_get_info, METH_VARARGS, "Get various misc info about x3"},
    /* null terminator */
    {NULL, NULL, 0, NULL}
};


/* ------------------------------------------------------------------------------------------------ *
     Thes functions set up the embedded environment for us to call out to modpython.py class 
     methods.  
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
       which handlers use to interact with c.
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

/* ----------------------------------------------------------------------------- */
   

int python_load() {
    /* Init the python engine and do init work on modpython.py
       This is called during x3 startup, and on a python reload
    */
    PyObject *pName;

    setenv("PYTHONPATH", "/home/rubin/afternet/services/x3/x3-run/", 1);
    Py_Initialize();
    Py_InitModule("svc", EmbMethods);
    /* TODO: get "modpython" from x3.conf */
    pName = PyString_FromString("modpython");
    base_module = PyImport_Import(pName);
    Py_DECREF(pName);
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
    Py_Finalize(); /* Shut down python enterpriter */
    return;
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

static MODCMD_FUNC(cmd_run) {
    /* run an arbitrary python command. This can include shell commands, so should be disabled on
       production, and needs to be handled extremely cautiously as far as access control
    */
    char *msg;
    msg = unsplit_string(argv + 1, argc - 1, NULL);
    char *args[] = {msg};
    python_call_handler("cmd_run", args, 1, cmd->parent->bot->nick, user?user->nick:"", channel?channel->name:"");
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

int python_init(void) {
    /* X3 calls this function on init of the module during startup. We use it to
       do all our setup tasks and bindings 
    */

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
    modcmd_register(python_module, "run",  cmd_run,  2,  MODCMD_REQUIRE_AUTHED, "flags", "+oper", NULL);
    modcmd_register(python_module, "command", cmd_command, 3, MODCMD_REQUIRE_STAFF, NULL);

//  Please help us by implimenting any of the callbacks listed as TODO below. They already exist
//  in x3, they just need handle_ bridges implimented. (see python_handle_join for an example)
//TODO:    reg_server_link_func(python_handle_server_link);
//TODO:    reg_new_user_func(python_handle_new_user);
//TODO:    reg_nick_change_func(python_handle_nick_change);
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
