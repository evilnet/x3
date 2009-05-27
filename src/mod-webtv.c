/* mod-webtv.c - WebTV Module for X3
 * Copyright 2007 X3 Development Team
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
 */

#include "chanserv.h"
#include "conf.h"
#include "modcmd.h"
#include "nickserv.h"
#include "opserv.h"
#include "saxdb.h"
#include "timeq.h"

#define MAX_CHANNELS_WHOIS      50

static const struct message_entry msgtab[] = {
    { "WBMSG_NOT_MARKED", "You are not a WebTV client." },

    { "WBMSG_NICK_PARAMS", "You need to specify a nickname." },
    { "WBMSG_NICK_SAME",   "You are already $b%s$b." },
    { "WBMSG_NICK_INVALID",   "The nickname $b%s$b is invalid." },
    { "WBMSG_NICK_IN_USE", "The nickname $b%s$b is in use, please choose another." },

    { "WBMSG_CHANNEL_BANNED",   "You are banned on %s." },
    { "WBMSG_CHANNEL_LIMIT",    "%s has reached the maximum allowed chatters." },
    { "WBMSG_CHANNEL_INVITE",   "%s is invite only." },
    { "WBMSG_CHANNEL_PASSWORD", "%s is password protected." },

    { "WBMSG_WHOIS_NICKIDENT",  "[%s] (%s@%s): %s" },
    { "WBMSG_WHOIS_CHANNELS",   "On %s" },
    { "WBMSG_WHOIS_SERVER",     "[%s] %s : %s" },
    { "WBMSG_WHOIS_OPER",       "[%s] is an IRC Operator" },
    { "WBMSG_WHOIS_SERVICE",    "[%s] is an IRC Service" },
    { "WBMSG_WHOIS_ACCOUNT",    "[%s] is logged in as %s" },
    { "WBMSG_WHOIS_REALHOST",   "[%s] realhost %s@%s %s" },
    { "WBMSG_WHOIS_SWHOIS",     "[%s] %s" },
    { "WBMSG_WHOIS_DNSBL",      "[%s] is DNSBL listed on %s" },
    { "WBMSG_WHOIS_CONNECTED",  "[%s] %s" },
    { "WBMSG_WHOIS_END",        "[%s] End of WHOIS list." },

    { "WBMSG_ALREADY_JOINED",   "I am already in $b%s$b." },
    { "WBMSG_JOIN_DONE",        "I have joined $b%s$b." },

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
    int required_mark;
    struct string_list *valid_marks;
} webtv_conf;

#define OPTION_FUNC(NAME) int NAME(struct svccmd *cmd, struct userNode *user, struct handle_info *hi, UNUSED_ARG(unsigned int override), unsigned int argc, char *argv[])
typedef OPTION_FUNC(option_func_t);

extern struct string_list *autojoin_channels;
const char *webtv_module_deps[] = { NULL };
static struct module *webtv_module;
static struct log_type *WB_LOG;
static char *his_servername;
static char *his_servercomment;


int check_mark(struct svccmd *cmd, struct userNode *user, UNUSED_ARG(struct handle_info *hi), UNUSED_ARG(unsigned int override),  UNUSED_ARG(unsigned int argc), UNUSED_ARG(char *argv[]))
{
    unsigned int y = 0;

    if ((webtv_conf.required_mark == 0) || IsOper(user))
        return 1;
    else {
        if (!user->mark) {
            reply("WBMSG_NOT_MARKED");
            return 0;
        }
        for (y = 0; y < webtv_conf.valid_marks->used; y++) {
            if (!strcasecmp(webtv_conf.valid_marks->list[y], user->mark))
                return 1;
        }
        reply("WBMSG_NOT_MARKED");
        return 0;
    }
}

static MODCMD_FUNC(cmd_nick)
{
    struct userNode *nick;

    if (!check_mark(cmd, user, NULL, 0, 0, NULL))
        return 0;

    if (argc < 2) {
        reply("WBMSG_NICK_PARAMS");
        return 0;
    }

    if (!strcasecmp(argv[1], user->nick)) {
        reply("WBMSG_NICK_SAME", argv[1]);
        return 0;
    }

    if (!is_valid_nick(argv[1])) {
        reply("WBMSG_NICK_INVALID", argv[1]);
        return 0;
    }

    nick = GetUserH(argv[1]);
    if (nick) {
        reply("WBMSG_NICK_IN_USE", argv[1]);
        return 0;
    }

    irc_svsnick(webtv, user, argv[1]);
    return 1;
}

void
webtv_ison(struct userNode *bot, struct userNode *tell, struct userNode *target, const char *message)
{
    struct modeNode *mn;
    unsigned int count, here_len, n, maxlen;
    char buff[MAXLEN];

    maxlen = tell->handle_info ? tell->handle_info->screen_width : 0;
    if (!maxlen)
        maxlen = MAX_LINE_SIZE;
    for (n=count=0; n<target->channels.used; n++) {
        mn = target->channels.list[n];
        if ((mn->channel->modes & (MODE_PRIVATE|MODE_SECRET)))
          continue;

        here_len = strlen(mn->channel->name);
        if ((count + here_len + 4) > maxlen) {
            buff[count] = 0;
            send_message(tell, bot, message, buff);
            count = 0;
        }
        if (mn->modes & MODE_CHANOP)
            buff[count++] = '@';
        if (mn->modes & MODE_HALFOP)
            buff[count++] = '%';
        if (mn->modes & MODE_VOICE)
            buff[count++] = '+';
        memcpy(buff+count, mn->channel->name, here_len);
        count += here_len;
        buff[count++] = ' ';
    }
    if (count) {
        buff[count] = 0;
        send_message(tell, bot, message, buff);
    }
}

static MODCMD_FUNC(cmd_whois)
{
    struct userNode *target;

    if (!check_mark(cmd, user, NULL, 0, 0, NULL))
        return 0;

    if (argc < 2) {
        reply("WBMSG_NICK_PARAMS");
        return 0;
    }

    target = GetUserH(argv[1]);
    if (target) {
        reply("WBMSG_WHOIS_NICKIDENT", target->nick, target->ident,
              IsFakeHost(target) ? target->fakehost : target->hostname, target->info);

        if ((target->channels.used <= MAX_CHANNELS_WHOIS) && !IsService(target))
            webtv_ison(cmd->parent->bot, user, target, "WBMSG_WHOIS_CHANNELS");

        if (target == user)
            reply("WBMSG_WHOIS_SERVER", target->nick, target->uplink->name, target->uplink->description);
        else {
            reply("WBMSG_WHOIS_SERVER", target->nick, his_servername ? his_servername : target->uplink->name,
                  his_servercomment ? his_servercomment : target->uplink->description);
        }

        if (IsOper(target))
            reply("WBMSG_WHOIS_OPER", target->nick);

        if (IsService(target))
            reply("WBMSG_WHOIS_SERVICE", target->nick);

        if (target->handle_info)
            reply("WBMSG_WHOIS_ACCOUNT", target->nick, target->handle_info->handle);

        if ((target == user) && (target->fakehost || IsHiddenHost(target))) 
            reply("WBMSG_WHOIS_REALHOST", target->nick, target->ident, target->hostname, irc_ntoa(&target->ip));

        if (target->handle_info) {
           if (target->handle_info->epithet)
               reply("WBMSG_WHOIS_SWHOIS", target->nick, target->handle_info->epithet);
        }
 
        if (target->mark)
               reply("WBMSG_WHOIS_DNSBL", target->nick, target->mark);

        reply("WBMSG_WHOIS_END", target->nick);
    } else {
        reply("MSG_NICK_UNKNOWN", argv[1]);
        return 0;
    }

    return 1;
}

void
part_all_channels(struct userNode *target)
{
    unsigned int n=0;
    struct modeNode *mn;

    for (n=0; n<target->channels.used; n++) {
        mn = target->channels.list[n];
        irc_svspart(webtv, target, mn->channel);
    }

    return;
}

static MODCMD_FUNC(cmd_sjoin)
{
    struct userNode *bot = cmd->parent->bot;

    if (!IsChannelName(argv[1])) {
        reply("MSG_NOT_CHANNEL_NAME");
        return 0;
    } else if (!(channel = GetChannel(argv[1]))) {
        channel = AddChannel(argv[1], now, NULL, NULL, NULL);
        AddChannelUser(bot, channel)->modes |= MODE_CHANOP;
    } else if (GetUserMode(channel, bot)) {
        reply("WBMSG_ALREADY_JOINED", channel->name);
        return 0;
    } else {
        struct mod_chanmode change;
        mod_chanmode_init(&change);
        change.argc = 1;
        change.args[0].mode = MODE_CHANOP;
        change.args[0].u.member = AddChannelUser(bot, channel);
        modcmd_chanmode_announce(&change);
    }
    irc_fetchtopic(bot, channel->name);
    reply("WBMSG_JOIN_DONE", channel->name);
    return 1;
}

static MODCMD_FUNC(cmd_join)
{
    struct chanNode *target;

    if (!check_mark(cmd, user, NULL, 0, 0, NULL))
        return 0;

    if(!(target = GetChannel(argv[1])))
    {
        reply("MSG_INVALID_CHANNEL");
        return 0;
    }

    if (trace_check_bans(user, target) == 1) {
        reply("WBMSG_CHANNEL_BANNED", argv[1]);
        return 0;
    }

    if (target->modes & MODE_INVITEONLY) {
        reply("WBMSG_CHANNEL_INVITE", argv[1]);
        return 0;
    }


    if (target->limit > 0) {
        if (target->members.used >= target->limit) {
             reply("WBMSG_CHANNEL_LIMIT", argv[1]);
             return 0;
        }
    }


    if (*target->key) {
         if (argc > 2) {
           if (strcmp(argv[2], target->key)) {
               reply("WBMSG_CHANNEL_PASSWORD", argv[1]);
               return 0;
           }
         } else {
             reply("WBMSG_CHANNEL_PASSWORD", argv[1]);
             return 0;
         }
    }

    part_all_channels(user);
    irc_svsjoin(webtv, user, target);
    return 1;
}

static MODCMD_FUNC(cmd_part)
{
    struct mod_chanmode change;
    struct chanNode *target;

    if (!check_mark(cmd, user, NULL, 0, 0, NULL))
        return 0;

    if(!(target = GetChannel(argv[1])))
    {
        reply("MSG_INVALID_CHANNEL");
        return 0;
    }

    mod_chanmode_init(&change);
    change.argc = 1;
    change.args[0].u.member = GetUserMode(target, user);
    if(!change.args[0].u.member)
    {
        if(argc)
            reply("MSG_CHANNEL_ABSENT", target->name);
        return 0;
    }

    irc_svspart(webtv, user, target);
    return 1;
}

static void
webtv_conf_read(void)
{
    dict_t conf_node;
    const char *str;
    struct string_list *strlist;

    str = "modules/webtv";
    if (!(conf_node = conf_get_data(str, RECDB_OBJECT))) {
        log_module(WB_LOG, LOG_ERROR, "config node `%s' is missing or has wrong type.", str);
        return;
    }

    str = database_get_data(conf_node, "required_mark", RECDB_QSTRING);
    webtv_conf.required_mark = str ? atoi(str) : 0;

    free_string_list(webtv_conf.valid_marks);
    strlist = database_get_data(conf_node, "valid_marks", RECDB_STRING_LIST);
    if(strlist)
        strlist = string_list_copy(strlist);
    else
        strlist = alloc_string_list(4);
    webtv_conf.valid_marks = strlist;

    str = conf_get_data("server/his_servername", RECDB_QSTRING);
    his_servername = str ? strdup(str) : NULL;
    str = conf_get_data("server/his_servercomment", RECDB_QSTRING);
    his_servercomment = str ? strdup(str) : NULL;
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
    modcmd_register(webtv_module, "nick",  cmd_nick,  1, 0, NULL);
    modcmd_register(webtv_module, "join",  cmd_join,  1, 0, NULL);
    modcmd_register(webtv_module, "part",  cmd_part,  1, 0, NULL);
    modcmd_register(webtv_module, "whois", cmd_whois, 1, 0, NULL);

    modcmd_register(webtv_module, "sjoin",  cmd_sjoin,  1, MODCMD_REQUIRE_AUTHED, "flags", "+oper", NULL);

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
        webtv = AddLocalUser(str, str, NULL, "WebTV IRC Service", modes);
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
