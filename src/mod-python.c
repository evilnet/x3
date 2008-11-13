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
    { "MSMSG_FOO", "foo there $b%s$b." },
    { NULL, NULL } /* sentenal */
};

static struct log_type *PY_LOG;
const char *python_module_deps[] = { NULL };
static struct module *python_module;


/* Called on shutdown of the module */
static void
python_cleanup(void)
{
    return;
}

static int
python_handle_join(struct modeNode *mNode)
{
    struct userNode *user = mNode->user;
    struct chanNode *channel = mNode->channel;

    PyRun_SimpleString("print 'Someone joined a channel somewhere'");
    return 0;
}

/* Called on init of the module during startup */
int python_init(void) {


    PY_LOG = log_register_type("Python", "file:python.log");
    reg_join_func(python_handle_join);
/*
    reg_auth_func(python_check_messages);
    reg_handle_rename_func(python_rename_account);
    reg_unreg_func(python_unreg_account);
    conf_register_reload(python_conf_read);
    reg_exit_func(python_cleanup);
    saxdb_register("python", python_saxdb_read, python_saxdb_write);
    python_module = module_register("python", MS_LOG, "mod-python.help", NULL);
    modcmd_register(python_module, "send",    cmd_send,    3, MODCMD_REQUIRE_AUTHED, NULL);
*/
    Py_Initialize();

    return 1;
}

int
python_finalize(void) {

    PyRun_SimpleString("print 'Hello, World of Python!'");

    return 1;
}

#endif /* WITH_PYTHON */
