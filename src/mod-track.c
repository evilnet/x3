/* mod-track.c - User surveillance module
 * Copyright 2002-2004 srvx Development Team
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

/* Adds new section to srvx.conf:
 * "modules" {
 *     "track" {
 *         // What data to show.
 *         "snomask" "nick,join,part,kick,new,del,auth,chanmode,umode";
 *         // Where to send track messages?
 *         "channel" "#wherever";
 *         // Which bot?
 *         "bot" "OpServ";
 *         // Show new users and joins from net joins?  (off by default)
 *         "show_bursts" "0";
 *     };
 * };
 */

#include "conf.h"
#include "chanserv.h"
#include "helpfile.h"
#include "nickserv.h"
#include "modcmd.h"
#include "proto.h"
#include "dict.h"
#include "hash.h"

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

/* track snomask definitions */
#define TRACK_NICK              0x0001 /* report nickchanges */
#define TRACK_JOIN              0x0002 /* report join/part */
#define TRACK_PART              0x0004 /* report parts */
#define TRACK_KICK              0x0008 /* report kicks */
#define TRACK_NEW               0x0010 /* report new users */
#define TRACK_DEL               0x0020 /* report quits */
#define TRACK_AUTH              0x0040 /* report auths */
#define TRACK_CHANMODE          0x0080 /* report channel modes */
#define TRACK_UMODE             0x0100 /* report user modes */

/* check track status */
#define check_track_nick(x)     ((x).snomask & TRACK_NICK)
#define check_track_join(x)     ((x).snomask & TRACK_JOIN)
#define check_track_part(x)     ((x).snomask & TRACK_PART)
#define check_track_kick(x)     ((x).snomask & TRACK_KICK)
#define check_track_new(x)      ((x).snomask & TRACK_NEW)
#define check_track_del(x)      ((x).snomask & TRACK_DEL)
#define check_track_auth(x)     ((x).snomask & TRACK_AUTH)
#define check_track_chanmode(x) ((x).snomask & TRACK_CHANMODE)
#define check_track_umode(x)    ((x).snomask & TRACK_UMODE)

/* set track status */
#define set_track_nick(x)       ((x).snomask |= TRACK_NICK)
#define set_track_join(x)       ((x).snomask |= TRACK_JOIN)
#define set_track_part(x)       ((x).snomask |= TRACK_PART)
#define set_track_kick(x)       ((x).snomask |= TRACK_KICK)
#define set_track_new(x)        ((x).snomask |= TRACK_NEW)
#define set_track_del(x)        ((x).snomask |= TRACK_DEL)
#define set_track_auth(x)       ((x).snomask |= TRACK_AUTH)
#define set_track_chanmode(x)   ((x).snomask |= TRACK_CHANMODE)
#define set_track_umode(x)      ((x).snomask |= TRACK_UMODE)
#define set_track_all(x)        ((x).snomask |= TRACK_NICK|TRACK_JOIN|TRACK_PART|TRACK_KICK|TRACK_NEW|TRACK_DEL|TRACK_AUTH|TRACK_CHANMODE|TRACK_UMODE)

/* clear track status */
#define clear_track_nick(x)     ((x).snomask &= ~TRACK_NICK)
#define clear_track_join(x)     ((x).snomask &= ~TRACK_JOIN)
#define clear_track_part(x)     ((x).snomask &= ~TRACK_PART)
#define clear_track_kick(x)     ((x).snomask &= ~TRACK_KICK)
#define clear_track_new(x)      ((x).snomask &= ~TRACK_NEW)
#define clear_track_del(x)      ((x).snomask &= ~TRACK_DEL)
#define clear_track_auth(x)     ((x).snomask &= ~TRACK_AUTH)
#define clear_track_chanmode(x) ((x).snomask &= ~TRACK_CHANMODE)
#define clear_track_umode(x)    ((x).snomask &= ~TRACK_UMODE)
#define clear_track_all(x)      ((x).snomask &= ~(TRACK_NICK|TRACK_JOIN|TRACK_PART|TRACK_KICK|TRACK_NEW|TRACK_DEL|TRACK_AUTH|TRACK_CHANMODE|TRACK_UMODE))

extern struct modcmd *opserv_define_func(const char *name, modcmd_func_t *func, int min_level, int reqchan, int min_argc);

extern time_t now;
static struct {
    struct chanNode *channel;
    struct userNode *bot;
    unsigned int snomask;
    unsigned int show_bursts : 1;
    unsigned int enabled : 1;
} track_cfg;
static char timestamp[16];
static dict_t track_db = NULL;

const char *track_module_deps[] = { NULL };

static int finalized;
int track_finalize(void);

#define TRACK(FORMAT, ARGS...) send_channel_message(track_cfg.channel, track_cfg.bot, "%s "FORMAT, timestamp , ## ARGS)
#define UPDATE_TIMESTAMP() strftime(timestamp, sizeof(timestamp), "[%H:%M:%S]", localtime(&now))

void 
add_track_user(struct userNode *user) 
{ 
    dict_insert(track_db, strdup(user->nick), user); 
}

static void 
del_track_user(const char *nick) 
{ 
    dict_remove(track_db, nick); 
}

static int
check_track_user(const char *nick)
{
       int found;
       if(!nick)
         return 0;
       dict_find(track_db, nick, &found);
       return found;
}

static void
parse_track_conf(char *line)
{
       char *t = NULL, *s = line;

       while(s)
       {
               if ((t = strchr(s, ',')))
                       *t++ = 0;

               switch (tolower(s[0]))
               {
                       case 'a':
                               if(!strcasecmp(s, "auth"))
                                       set_track_auth(track_cfg);
                               break;
                       case 'c':
                               if(!strcasecmp(s, "chanmode"))
                                       set_track_chanmode(track_cfg);
                               break;
                       case 'd':
                               if(!strcasecmp(s, "del"))
                                       set_track_del(track_cfg);
                               break;
                       case 'j':
                               if(!strcasecmp(s, "join"))
                                       set_track_join(track_cfg);
                               break;
                       case 'k':
                               if(!strcasecmp(s, "kick"))
                                       set_track_kick(track_cfg);
                               break;
                       case 'n':
                               if(!strcasecmp(s, "new"))
                                       set_track_new(track_cfg);
                               if(!strcasecmp(s, "nick"))
                                       set_track_nick(track_cfg);
                               break;
                       case 'p':
                               if(!strcasecmp(s, "part"))
                                       set_track_nick(track_cfg);
                               break;
                       case 'u':
                               if(!strcasecmp(s, "umode"))
                                       set_track_umode(track_cfg);
                               break;
               }
               s = t;
       }
}

static void
track_nick_change(struct userNode *user, const char *old_nick) {
    if (!track_cfg.enabled) return;

    if(check_track_user(old_nick)) {
        del_track_user(old_nick);
        add_track_user(user);
        if (check_track_nick(track_cfg))
        {
               UPDATE_TIMESTAMP();
               TRACK("$bNICK$b change %s -> %s", old_nick, user->nick);
        }
    }
}

static int
track_join(struct modeNode *mNode) {
    struct userNode *user = mNode->user;
    struct chanNode *chan = mNode->channel;
    if (!track_cfg.enabled) return 0;
    if (user->uplink->burst && !track_cfg.show_bursts) return 0;
    if (check_track_join(track_cfg) && check_track_user(user->nick))
    {
           UPDATE_TIMESTAMP();
           if (chan->members.used == 1) {
                   TRACK("$bCREATE$b %s by %s", chan->name, user->nick);
           } else {
                   TRACK("$bJOIN$b %s by %s", chan->name, user->nick);
           }
    }
    return 0;
}

static void
track_part(struct modeNode *mn, const char *reason) {
    if (!track_cfg.enabled) return;
    if (mn->user->dead) return;
    if (check_track_part(track_cfg) && check_track_user(mn->user->nick))
    {
           UPDATE_TIMESTAMP();
           TRACK("$bPART$b %s by %s (%s)", mn->channel->name, mn->user->nick, reason ? reason : "");
    }
}

static void
track_kick(struct userNode *kicker, struct userNode *victim, struct chanNode *chan) {
    if (!track_cfg.enabled) return;
    if (check_track_kick(track_cfg) && ((check_track_user(kicker->nick) || check_track_user(victim->nick))))
    {
           UPDATE_TIMESTAMP();
           TRACK("$bKICK$b %s from %s by %s", victim->nick, chan->name, (kicker ? kicker->nick : "some server"));
    }
}

static int
track_new_user(struct userNode *user) {

    if (!track_cfg.enabled) return 0;
    if (user->uplink->burst && !track_cfg.show_bursts) return 0;
    if (check_track_new(track_cfg) && check_track_user(user->nick))
    {
           UPDATE_TIMESTAMP();
           TRACK("$bNICK$b %s %s@%s [%s] on %s", user->nick, user->ident, user->hostname, irc_ntoa(&user->ip), user->uplink->name);
    }
    return 0;
}

static void
track_del_user(struct userNode *user, struct userNode *killer, const char *why) {
    if (!track_cfg.enabled) return;
    if (check_track_del(track_cfg) && (check_track_user(user->nick) || (killer && check_track_user(killer->nick))))
    {
           UPDATE_TIMESTAMP();
           if (killer) {
                   TRACK("$bKILL$b %s (%s@%s, on %s) by %s (%s)", user->nick, user->ident, user->hostname, user->uplink->name, killer->nick, why);
           } else {
                   TRACK("$bQUIT$b %s (%s@%s, on %s) (%s)", user->nick, user->ident, user->hostname, user->uplink->name, why);
           }
           del_track_user(user->nick);
    }
}

static void
track_auth(struct userNode *user, UNUSED_ARG(struct handle_info *old_handle)) {
    if (!track_cfg.enabled) return;
    if (user->uplink->burst && !track_cfg.show_bursts) return;
    if (user->handle_info && (check_track_auth(track_cfg) && check_track_user(user->nick))) {
        UPDATE_TIMESTAMP();
        TRACK("$bAUTH$b %s!%s@%s [%s] on %s as %s", user->nick, user->ident, user->hostname,
                       irc_ntoa(&user->ip), user->uplink->name, user->handle_info->handle);
    }
}

static void
track_user_mode(struct userNode *user, const char *mode_change) {
       if (!track_cfg.enabled) return;
       if (user->uplink->burst && !track_cfg.show_bursts) return;
       if (!mode_change[1]) return; /* warning there has to be atleast one char in the buffer */
       if(check_track_umode(track_cfg) && check_track_user(user->nick))
       {
               UPDATE_TIMESTAMP();
               TRACK("$bUMODE$b %s %s", user->nick, mode_change);
       }
}

static void
track_oper(struct userNode *user) {
       if (!track_cfg.enabled) return;
       if (user->uplink->burst && !track_cfg.show_bursts) return;
       UPDATE_TIMESTAMP();
       TRACK("$bOPER$b %s!%s@%s [%s] on %s", user->nick, user->ident, user->hostname, irc_ntoa(&user->ip), user->uplink->name);
}

static void
track_channel_mode(struct userNode *who, struct chanNode *channel, char **modes, unsigned int argc)
{
       if (!track_cfg.enabled) return;
       if(who)
       {
               if (who->uplink->burst && !track_cfg.show_bursts) return;
               if (!check_track_chanmode(track_cfg) || !check_track_user(who->nick)) return;
       } else
               return;

       static char targets[MAXLEN], string[MAXLEN];
       struct userNode *un = NULL;
       char *tmp = NULL, *tg = NULL, *md = NULL;
       int add = 0;

       string[0] = 0;
       targets[0] = 0;

       if (argc > 0)
               unsplit_string(modes, argc, string);
       else
               strcpy(string, *modes);

       if((tg = strchr(string, ' ')))
       {
               *tg++ = 0;
               for(md = string; *md; md++)
               {
                       if (*md == '+')
                       {
                               add = 1;
                               md++;
                       }
                      if (*md == '-')
                       {
                               add = 0;
                               md++;
                       }
                       switch(*md)
                      {
                               case 'k':
                                       {
                                               strcat(targets, " ");
                                               if ((tmp = strchr(tg, ' ')))
                                                       *tmp++ = 0;
                                               strcat(targets, tg);
                                               if(tmp)
                                                       tg = tmp;
                                               break;
                                       }
                               case 'l':
                                       {
                                               if(add)
                                               {
                                                       strcat(targets, " ");
                                                       if ((tmp = strchr(tg, ' ')))
                                                               *tmp++ = 0;
                                                       strcat(targets, tg);
                                                       if(tmp)
                                                               tg = tmp;
                                                       break;
                                               }
                                       }
                               case 'b':
                                       {
                                               strcat(targets, " ");
                                               if ((tmp = strchr(tg, ' ')))
                                                       *tmp++ = 0;
                                               strcat(targets, tg);
                                               if(tmp)
                                                       tg = tmp;
                                               break;
                                       }
                               case 'e':
                                       {
                                               strcat(targets, " ");
                                               if ((tmp = strchr(tg, ' ')))
                                                       *tmp++ = 0;
                                               strcat(targets, tg);
                                               if(tmp)
                                                       tg = tmp;
                                               break;
                                       }
                               case 'o':
                                       {
                                               strcat(targets, " ");
                                               if ((tmp = strchr(tg, ' ')))
                                                       *tmp++ = 0;
                                               if((un = GetUserN(tg)))
                                                       strcat(targets, un->nick);
                                               else
                                                       strcat(targets, tg);
                                               if(tmp)
                                                       tg = tmp;
                                               break;
                                       }
                               case 'v':
                                       {
                                               strcat(targets, " ");
                                               if ((tmp = strchr(tg, ' ')))
                                                       *tmp++ = 0;
                                               if((un = GetUserN(tg)))
                                                       strcat(targets, un->nick);
                                               else
                                                       strcat(targets, tg);
                                               if(tmp)
                                                       tg = tmp;
                                               break;
                                       }
                       }
               }
       }
       UPDATE_TIMESTAMP();
       if (who)
               TRACK("$bMODE$b %s %s%s by %s", channel->name, string, targets, who->nick);
       else
               TRACK("$bMODE$b %s %s%s", channel->name, string, targets);
}

static void
check_track_state(struct userNode *user)
{
       send_message_type(4, user, track_cfg.bot, "TRACK is tracking: %s%s%s%s%s%s%s%s%s",
                       check_track_nick(track_cfg) ? " nick":"", check_track_join(track_cfg) ? " join":"",
                       check_track_part(track_cfg) ? " part":"", check_track_kick(track_cfg) ? " kick":"",
                       check_track_new(track_cfg) ? " new":"", check_track_del(track_cfg) ? " del":"",
                       check_track_auth(track_cfg) ? " auth":"", check_track_chanmode(track_cfg) ? " chanmode":"",
                       check_track_umode(track_cfg) ? " umode":"");
}

MODCMD_FUNC(cmd_track)
{
       unsigned int i, add;
       const char *data;
       char changed = false;

       if(argc == 1)
       {
               svccmd_send_help_brief(user, track_cfg.bot, cmd);
               check_track_state(user);
               return 0;
       }

	for(i = 1; i < argc; i++)
	{
		data = argv[i];
		add = 2;
		changed = true;

		if(*data == '+')
			add = 1;
		if(*data == '-')
			add = 0;

		if(add == 2)
		{
			if ((!strcasecmp(data, "all")))
			{
				set_track_all(track_cfg);
				check_track_state(user);
				TRACK("$bALERT$b TRACK fully enabled by %s", user->nick);
			}
			else if (!strcasecmp(data, "none"))
			{
				clear_track_all(track_cfg);
				check_track_state(user);
				TRACK("$bALERT$b TRACK disabled by %s", user->nick);
			}
			else
                        {
                                send_message_type(4, user, track_cfg.bot, "Unrecognised parameter: %s", data);
                                svccmd_send_help_brief(user, track_cfg.bot, cmd);
                        }
			return 0;
		}

		data++;

                if(!strcasecmp(data, "auth")) {
                        if (add)
                                set_track_auth(track_cfg);
                        else
                                clear_track_auth(track_cfg);
                } else if(!strcasecmp(data, "chanmode")) {
                        if (add)
                                set_track_chanmode(track_cfg);
                        else
                                clear_track_chanmode(track_cfg);
                } else if(!strcasecmp(data, "del")) {
                        if (add)
                                set_track_del(track_cfg);
                        else
                                clear_track_del(track_cfg);
                } else if(!strcasecmp(data, "join")) {
                        if(add)
                                set_track_join(track_cfg);
                        else
                                clear_track_join(track_cfg);
                } else if(!strcasecmp(data, "kick")) {
                        if(add)
                                set_track_kick(track_cfg);
                        else
                                clear_track_kick(track_cfg);
                } else if(!strcasecmp(data, "new")) {
                        if(add)
                                set_track_new(track_cfg);
                        else
                                clear_track_new(track_cfg);
                } else if(!strcasecmp(data, "nick")) {
                        if(add)
                                set_track_nick(track_cfg);
                        else
                                clear_track_nick(track_cfg);
                } else if(!strcasecmp(data, "part")) {
                        if(add)
                                set_track_part(track_cfg);
                        else
                                clear_track_part(track_cfg);
                } else if(!strcasecmp(data, "umode")) {
                        if(add)
                                set_track_umode(track_cfg);
                        else
                                clear_track_umode(track_cfg);
                } else {
                    TRACK("Error, Unknown value %s", data);
		}
	}
	check_track_state(user);

	if(changed)
	{
 		char buf[256];
		unsigned int pos = 0;
		memset(buf, 0, sizeof(buf));
		for(i = 1; i < argc; i++)
		{
			unsigned int len;
			data = argv[i];
			len = strlen(data);
			if(pos + len > sizeof(buf))
				break;
			strcpy(&buf[pos], data);
			pos += len;
		}

		UPDATE_TIMESTAMP();
		TRACK("$bALERT$b TRACK command called with parameters '%s' by %s",
				buf, user->nick);
	}
	return 0;
}

MODCMD_FUNC(cmd_deltrack)
{
	struct userNode *un = NULL;

	if((argc > 1) && (un = dict_find(clients, argv[1], NULL)))
	{
		if(check_track_user(un->nick))
		{
			del_track_user(un->nick);
			UPDATE_TIMESTAMP();
			TRACK("$bALERT$b No longer monitoring %s!%s@%s on %s requested by %s",
					un->nick, un->ident, un->hostname, un->uplink->name, user->nick);
		}
		else
			send_message_type(4, user, track_cfg.bot, "This nick isn't monitored.");
	}
	else
    {
		send_message_type(4, user, track_cfg.bot, "No nick or invalid nick specified.");
        svccmd_send_help_brief(user, track_cfg.bot, cmd);
    }
	return 0;
}

MODCMD_FUNC(cmd_addtrack)
{
    struct userNode *un = NULL;

    if((argc > 1) && (un = dict_find(clients, argv[1], NULL)))
    {
	add_track_user(un);
	UPDATE_TIMESTAMP();
	TRACK("$bALERT$b Manually enabled monitoring of %s!%s@%s on %s requested by %s",
			un->nick, un->ident, un->hostname, un->uplink->name, user->nick);
        send_message_type(4, user, track_cfg.bot, "Now tracking %s!%s@%s on %s", un->nick,un->ident,un->hostname, un->uplink->name);
    }
    else
    {
	send_message_type(4, user, track_cfg.bot, "No nick or invalid nick specified.");
        svccmd_send_help_brief(user, track_cfg.bot, cmd);
    }
    return 0;
}

MODCMD_FUNC(cmd_listtrack)
{
	dict_iterator_t it, next;
	if (track_db == NULL) return 0;
	struct userNode *un = NULL;
	send_message_type(4, user, track_cfg.bot, "Currently tracking:");
	for (it=dict_first(track_db); it; it=next) {
		next = iter_next(it);
		un = it->data;
		send_message_type(4, user, track_cfg.bot, "%s!%s@%s [%s] on %s",
				un->nick, un->ident, un->hostname, irc_ntoa(&un->ip), un->uplink->name);
	}
	send_message_type(4, user, track_cfg.bot, "End of track list.");
	return 0;
}

static void
track_conf_read(void) {
    dict_t node;
    char *str;

    node = conf_get_data("modules/track", RECDB_OBJECT);
    if (!node)
        return;
    str = database_get_data(node, "snomask", RECDB_QSTRING);
    if (!str)
	    track_cfg.snomask = TRACK_NICK|TRACK_KICK|TRACK_JOIN|TRACK_PART|TRACK_CHANMODE|TRACK_NEW|TRACK_DEL|TRACK_AUTH;
    else
	    parse_track_conf(str);
    str = database_get_data(node, "channel", RECDB_QSTRING);
    if (!str)
        return;
    // XXX - dont do addchannel if the channel is being shared with
    // another module:
    track_cfg.channel = AddChannel(str, now, "+sntOm", NULL, NULL);
    if (!track_cfg.channel)
        return;
    str = database_get_data(node, "show_bursts", RECDB_QSTRING);
    track_cfg.show_bursts = str ? enabled_string(str) : 0;
    track_cfg.enabled = 1;
    if (finalized)
        track_finalize();
}

void
track_cleanup(void) {
    track_cfg.enabled = 0;
    unreg_del_user_func(track_del_user);
    dict_delete(track_db);
}

int
track_init(void) {
    track_db = dict_new();
    dict_set_free_keys(track_db, free);

    reg_exit_func(track_cleanup);
    conf_register_reload(track_conf_read);
    reg_nick_change_func(track_nick_change);
    reg_join_func(track_join);
    reg_part_func(track_part);
    reg_kick_func(track_kick);
    reg_new_user_func(track_new_user);
    reg_del_user_func(track_del_user);
    reg_auth_func(track_auth);
    reg_channel_mode_func(track_channel_mode);
    reg_user_mode_func(track_user_mode);
    reg_oper_func(track_oper);
    opserv_define_func("TRACK", cmd_track, 800, 0, 0);
    opserv_define_func("DELTRACK", cmd_deltrack, 800, 0, 0);
    opserv_define_func("ADDTRACK", cmd_addtrack, 800, 0, 0);
    opserv_define_func("LISTTRACK", cmd_listtrack, 800, 0, 0);
    return 1;
}

int
track_finalize(void) {
    struct mod_chanmode change;
    dict_t node;
    char *str;

    finalized = 1;
    node = conf_get_data("modules/track", RECDB_OBJECT);
    if (!node)
        return 0;
    str = database_get_data(node, "snomask", RECDB_QSTRING);
    if (!str)
	    track_cfg.snomask = TRACK_NICK|TRACK_KICK|TRACK_JOIN|TRACK_PART|TRACK_CHANMODE|TRACK_NEW|TRACK_DEL|TRACK_AUTH;
    else
	    parse_track_conf(str);
    str = database_get_data(node, "bot", RECDB_QSTRING);
    if (!str)
        return 0;
    track_cfg.bot = GetUserH(str);
    if (!track_cfg.bot)
        return 0;
    mod_chanmode_init(&change);
    change.argc = 1;
    change.args[0].mode = MODE_CHANOP;
    change.args[0].u.member = AddChannelUser(track_cfg.bot, track_cfg.channel);
    mod_chanmode_announce(track_cfg.bot, track_cfg.channel, &change);
    return 1;
}


