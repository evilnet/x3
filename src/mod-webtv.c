/* mod-webtv.c - WebTV Module for X3
 * Copyright 2007 X3 Development Team
 *
 * This file is part of x3.
 *
 * x3 is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
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

/*
 *
 * /msg opserv bind opserv service *modcmd.joiner
 * /msg opserv bind opserv service\ add *modcmd.service\ add
 * /msg opserv bind opserv service\ rename *modcmd.service\ rename
 * /msg opserv bind opserv service\ trigger *modcmd.service\ trigger
 * /msg opserv bind opserv service\ remove *modcmd.service\ remove
 * Add the bot:
 * /msg opserv service add IRC WebTV Service Bot
 * /msg opserv bind IRC help *modcmd.help
 * Restart X3 with the updated conf file (as above, butwith "bot"
 * "IRC"), and bind the commands to it:
 * /msg opserv bind IRC * *webtv.*
 * /msg opserv bind IRC set *webtv.set
 */

#include "chanserv.h"
#include "conf.h"
#include "modcmd.h"
#include "nickserv.h"
#include "opserv.h"
#include "saxdb.h"
#include "timeq.h"

static const struct message_entry msgtab[] = {
    { "MSMSG_CANNOT_SEND", "You cannot send to account $b%s$b." },

    { NULL, NULL }
};

struct userNode *webtv;

#define WEBTV_FUNC(NAME)         MODCMD_FUNC(NAME)
#define WEBTV_SYNTAX()           svccmd_send_help_brief(user, webtv, cmd)
#define WEBTV_MIN_PARAMS(N)      if(argc < (N)) {            \
                                     reply("MSG_MISSING_PARAMS", argv[0]); \
                                     WEBTV_SYNTAX(); \
                                     return 0; }

static struct {
    struct userNode *bot;
} webtv_conf;

#define OPTION_FUNC(NAME) int NAME(struct svccmd *cmd, struct userNode *user, struct handle_info *hi, UNUSED_ARG(unsigned int override), unsigned int argc, char *argv[])
typedef OPTION_FUNC(option_func_t);

extern struct string_list *autojoin_channels;
const char *webtv_module_deps[] = { NULL };
static struct module *webtv_module;
static struct log_type *WB_LOG;







static void
webtv_conf_read(void)
{
    dict_t conf_node;
    const char *str;

    str = "modules/webtv";
    if (!(conf_node = conf_get_data(str, RECDB_OBJECT))) {
        log_module(WB_LOG, LOG_ERROR, "config node `%s' is missing or has wrong type.", str);
        return;
    }
}

static void
webtv_cleanup(void)
{
}

int
webtv_init(void)
{
    WB_LOG = log_register_type("WebTV", "file:webtv.log");

    conf_register_reload(webtv_conf_read);
    reg_exit_func(webtv_cleanup);

    webtv_module = module_register("WebTV", WB_LOG, "mod-webtv.help", NULL);
/*
    modcmd_register(webtv_module, "send",    cmd_send,    3, MODCMD_REQUIRE_AUTHED, NULL);
    modcmd_register(webtv_module, "expire",  cmd_expire,  1, MODCMD_REQUIRE_AUTHED, "flags", "+oper", NULL);
*/
    message_register_table(msgtab);
    return 1;
}

int
webtv_finalize(void) {
    struct chanNode *chan;
    unsigned int i;
    dict_t conf_node;
    const char *str;

    str = "modules/webtv";
    if (!(conf_node = conf_get_data(str, RECDB_OBJECT))) {
        log_module(WB_LOG, LOG_ERROR, "config node `%s' is missing or has wrong type.", str);
        return 0;
    }

    str = database_get_data(conf_node, "bot", RECDB_QSTRING);
    if (str) {
        webtv = webtv_conf.bot;
        const char *modes = conf_get_data("modules/webtv/modes", RECDB_QSTRING);
        webtv = AddService(str, modes ? modes : NULL, "WebTV IRC Service", NULL);
    } else {
        log_module(WB_LOG, LOG_ERROR, "database_get_data for webtv_conf.bot failed!");
        exit(1);
    }

    if (autojoin_channels && webtv) {
        for (i = 0; i < autojoin_channels->used; i++) {
            chan = AddChannel(autojoin_channels->list[i], now, "+nt", NULL, NULL);
            AddChannelUser(webtv, chan)->modes |= MODE_CHANOP;
        }
    }

    return 1;
}
