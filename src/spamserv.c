/* spamserv.c - anti spam service
 * Copyright 2004 feigling
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.  Important limitations are
 * listed in the COPYING file that accompanies this software.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, email evilnet-devel@lists.sourceforge.net.
 *
 * $Id$
 */

#include "conf.h"
#include "spamserv.h"
#include "chanserv.h"
#include "helpfile.h"
#include "global.h"
#include "modcmd.h"
#include "saxdb.h"
#include "timeq.h"
#include "gline.h"

#define SPAMSERV_CONF_NAME           "services/spamserv"

#define KEY_EXCEPTIONS               "exceptions"
#define KEY_BADWORDS                 "badwords"
#define KEY_FLAGS                    "flags"
#define KEY_INFO                     "info"
#define KEY_EXPIRY                   "expiry"
#define KEY_TRUSTED_HOSTS	     "trusted"
#define KEY_CHANNELS		     "channel"
#define KEY_ISSUER		     "issuer"
#define KEY_ISSUED		     "issued"
#define KEY_TRUSTED_ACCOUNTS	     "trusted"
#define KEY_DEBUG_CHANNEL            "debug_channel"
#define KEY_GLOBAL_EXCEPTIONS        "global_exceptions"
#define KEY_GLOBAL_BADWORDS          "global_badwords"
#define KEY_NETWORK_RULES            "network_rules"
#define KEY_TRIGGER                  "trigger"
#define KEY_SHORT_BAN_DURATION       "short_ban_duration"
#define KEY_LONG_BAN_DURATION        "long_ban_duration"
#define KEY_GLINE_DURATION           "gline_duration"
#define KEY_EXCEPTION_MAX            "exception_max"
#define KEY_EXCEPTION_MIN_LEN        "exception_min_len"
#define KEY_EXCEPTION_MAX_LEN        "exception_max_len"
#define KEY_BADWORD_MAX              "badword_max"
#define KEY_BADWORD_MIN_LEN          "badword_min_len"
#define KEY_BADWORD_MAX_LEN          "badword_max_len"
#define KEY_ADV_CHAN_MUST_EXIST      "adv_chan_must_exist"
#define KEY_STRIP_MIRC_CODES         "strip_mirc_codes"
#define KEY_ALLOW_MOVE_MERGE         "allow_move_merge"
#define KEY_EXCEPTLEVEL              "exceptlevel"

#define SPAMSERV_FUNC(NAME)	MODCMD_FUNC(NAME)
#define SPAMSERV_SYNTAX()	svccmd_send_help(user, spamserv, cmd)
#define SPAMSERV_MIN_PARMS(N) do { \
(void)argv; \
  if(argc < N) { \
    ss_reply(MSG_MISSING_PARAMS, argv[0]); \
    SPAMSERV_SYNTAX(); \
    return 0; } } while(0)

struct userNode		*spamserv;
static struct module	*spamserv_module;
static struct service	*spamserv_service;
static struct log_type	*SS_LOG;
static unsigned long	crc_table[256];

dict_t registered_channels_dict;
dict_t connected_users_dict;
dict_t killed_users_dict;

#define SSFUNC_ARGS             user, channel, argc, argv, cmd

#define spamserv_notice(target, format...) send_message(target , spamserv , ## format)
#define spamserv_debug(format...) do { if(spamserv_conf.debug_channel) send_channel_notice(spamserv_conf.debug_channel , spamserv , ## format); } while(0)
#define ss_reply(format...)	send_message(user , spamserv , ## format)

#define SET_SUBCMDS_SIZE 14

const char *set_subcommands[SET_SUBCMDS_SIZE] = {"EXCEPTLEVEL", "SPAMLIMIT", "BADREACTION", "ADVREACTION", "WARNREACTION", "ADVSCAN", "SPAMSCAN", "BADWORDSCAN", "CHANFLOODSCAN", "JOINFLOODSCAN", "SCANCHANOPS", "SCANHALFOPS", "SCANVOICED"};

extern struct string_list *autojoin_channels;
static void spamserv_clear_spamNodes(struct chanNode *channel);
static void spamserv_punish(struct chanNode *channel, struct userNode *user, time_t expires, char *reason, int ban);
static unsigned long crc32(const char *text);

#define BINARY_OPTION(arguments...)	return binary_option(arguments, user, channel, argc, argv);
#define MULTIPLE_OPTION(arguments...)	return multiple_option(arguments, values, ArrayLength(values), user, channel, argc, argv);

static const struct message_entry msgtab[] = {
    { "SSMSG_CHANNEL_OPTIONS",         "Channel Options:" },
    { "SSMSG_STRING_VALUE",            "$b%s$b%s" },
    { "SSMSG_NUMERIC_VALUE",           "$b%s$b%d - %s" },
    { "SSMSG_INVALID_NUM_SET",         "$b'%d'$b is an invalid %s setting." },
    { "SSMSG_INVALID_OPTION",          "$b%s$b is not a valid %s option." },
    { "SSMSG_INVALID_BINARY",          "$b%s$b is an invalid binary value." },

    { "SSMSG_NOT_REGISTERED",          "$b%s$b has not been registered with $b$X$b." },
    { "SSMSG_NOT_REGISTERED_CS",       "$b%s$b has not been registered with $b$C$b." },
    { "SSMSG_ALREADY_REGISTERED",      "$b%s$b is already registered." },
    { "SSMSG_DEBUG_CHAN",              "You may not register the debug channel." },
    { "SSMSG_SUSPENDED_CS",            "$b$C$b access to $b%s$b has been temporarily suspended, thus you can't %s it." },
    { "SSMSG_SUSPENDED",               "$b$X$b access to $b%s$b has been temporarily suspended." },
    { "SSMSG_NO_REGISTER",             "Due to an error it was not possible to register $b%s$b." },
    { "SSMSG_REG_SUCCESS",             "Channel $b%s$b registered." },
    { "SSMSG_UNREG_SUCCESS",           "$b%s$b has been unregistered." },
    { "SSMSG_NO_ACCESS",               "You lack sufficient access to use this command." },
    { "SSMSG_MUST_BE_OPER",            "You must be an irc operator to set this option." },
    { "SSMSG_CONFIRM_UNREG",           "To confirm this unregistration, you must append 'CONFIRM' to the end of your command. For example, 'unregister CONFIRM'." },

    { "SSMSG_NO_EXCEPTIONS",           "No words found in the exception list." },
    { "SSMSG_NO_SUCH_EXCEPTION",       "Word $b%s$b not found in the exception list." },
    { "SSMSG_EXCEPTION_LIST",          "The following words are in the exception list:" },
    { "SSMSG_EXCEPTION_ADDED",         "Word $b%s$b added to the exception list." },
    { "SSMSG_EXCEPTION_DELETED",       "Word $b%s$b deleted from the exception list." },
    { "SSMSG_EXCEPTION_IN_LIST",       "The word $b%s$b is already in the exception list." },
    { "SSMSG_EXCEPTION_MAX",           "The exception list has reached the maximum exceptions (max %lu). Delete a word to add another one." },
    { "SSMSG_EXCEPTION_TOO_SHORT",     "The word must be at least %lu characters long." },
    { "SSMSG_EXCEPTION_TOO_LONG",      "The word may not be longer than %lu characters." },

    { "SSMSG_NO_BADWORDS",             "No words found in the badword list." },
    { "SSMSG_NO_SUCH_BADWORD",         "Word $b%s$b not found in the badword list." },
    { "SSMSG_BADWORD_LIST",            "The following words are in the badword list:" },
    { "SSMSG_BADWORD_ADDED",           "Word $b%s$b added to the badword list." },
    { "SSMSG_BADWORD_DELETED",         "Word $b%s$b deleted from the badword list." },
    { "SSMSG_BADWORD_IN_LIST",         "The word $b%s$b is already in the badword list." },
    { "SSMSG_BADWORD_MAX",             "The badword list has reached the maximum badwords (max %lu). Delete a word to add another one." },
    { "SSMSG_BADWORD_TOO_SHORT",       "The word must be at least %lu characters long." },
    { "SSMSG_BADWORD_TOO_LONG",        "The word may not be longer than %lu characters." },

    { "SSMSG_STATUS",                  "$bStatus:$b" },
    { "SSMSG_STATUS_USERS",            "Total Users Online:  %u" },
    { "SSMSG_STATUS_CHANNELS",         "Registered Channels: %u" },
    { "SSMSG_STATUS_MEMORY",           "$bMemory Information:$b" },
    { "SSMSG_STATUS_CHANNEL_LIST",     "$bRegistered Channels:$b" },
    { "SSMSG_STATUS_NO_CHANNEL",       "No channels registered." },

    { "SSMSG_WARNING_T",                "%s is against the network rules" },
    { "SSMSG_WARNING_2_T",              "You are violating the network rules" },
    { "SSMSG_WARNING_RULES_T",          "%s is against the network rules. Read the network rules at %s" },
    { "SSMSG_WARNING_RULES_2_T",        "You are violating the network rules. Read the network rules at %s" },

    { "SSMSG_ALREADY_TRUSTED", "Account $b%s$b is already trusted." },
    { "SSMSG_NOT_TRUSTED", "Account $b%s$b is not trusted." },
    { "SSMSG_ADDED_TRUSTED", "Added %s to the global trusted-accounts list" },
    { "SSMSG_ADDED_TRUSTED_CHANNEL", "Added %s to the trusted-accounts list for channel %s." },
    { "SSMSG_REMOVED_TRUSTED", "Removed %s from the global trusted-accounts list." },
    { "SSMSG_REMOVED_TRUSTED_CHANNEL", "Removed %s from channel %s trusted-account list." },
    { "SSMSG_TRUSTED_LIST", "$bTrusted Accounts$b" },
    { "SSMSG_TRUSTED_LIST_HEADER", "Account         Added By   Time" },
    { "SSMSG_HOST_IS_TRUSTED",      "%-15s %-10s set %s ago" },
    { "SSMSG_TRUSTED_LIST_BAR", "----------------------------------------" },
    { "SSMSG_TRUSTED_LIST_END", "---------End of Trusted Accounts--------" },
    { "SSMSG_HOST_NOT_TRUSTED", "%s does not have a special trust." },

    { "SSMSG_MUST_BE_HELPING", "You must have security override (helping mode) on to use this command." },

    { "SSMSG_SET_EXCEPTLEVEL", "$bExceptLevel$b   %d." }, 

    { NULL, NULL }
};

#define SSMSG_DEBUG_KICK              "Kicked user $b%s$b from $b%s$b, reason: %s"
#define SSMSG_DEBUG_BAN               "Banned user $b%s$b from $b%s$b, reason: %s"
#define SSMSG_DEBUG_KILL              "Killed user $b%s$b, last violation in $b%s$b"
#define SSMSG_DEBUG_GLINE             "Glined user $b%s$b, host $b%s$b, last violation in $b%s$b"
#define SSMSG_DEBUG_RECONNECT         "Killed user $b%s$b reconnected to the network"

#define SSMSG_SPAM                    "Spamming"
#define SSMSG_FLOOD                   "Flooding the channel/network"
#define SSMSG_ADV                     "Advertising"
#define SSMSG_BAD                     "Badwords"
#define SSMSG_JOINFLOOD               "Join flooding the channel"

#define SSMSG_WARNING                  "%s is against the network rules"
#define SSMSG_WARNING_2                "You are violating the network rules"
#define SSMSG_WARNING_RULES            "%s is against the network rules. Read the network rules at %s"
#define SSMSG_WARNING_RULES_2          "You are violating the network rules. Read the network rules at %s"

/*
#define SSMSG_WARNING                 "SSMSG_WARNING_T"
#define SSMSG_WARNING_2               "SSMSG_WARNING_2_T"
#define SSMSG_WARNING_RULES           "SSMSG_WARNING_RULES_T"
#define SSMSG_WARNING_RULES_2         "SSMSG_WARNING_RULES_2_T"
*/

static dict_t spamserv_trusted_accounts;

static struct
{
	struct chanNode *debug_channel;
	struct string_list *global_exceptions;
	struct string_list *global_badwords;
	const char *network_rules;
	unsigned char trigger;
	unsigned long short_ban_duration;
	unsigned long long_ban_duration;
	unsigned long gline_duration;
	unsigned long exception_max;
	unsigned long exception_min_len;
	unsigned long exception_max_len;
	unsigned long badword_max;
	unsigned long badword_min_len;
	unsigned long badword_max_len;
	unsigned int adv_chan_must_exist : 1;
	unsigned int strip_mirc_codes : 1;
	unsigned int allow_move_merge : 1;
	unsigned long untrusted_max;
} spamserv_conf;

struct trusted_account {
    char *account;
    struct string_list *channel;
    char *issuer;
    unsigned long limit;
    time_t issued;
};

/***********************************************/
/*                   Channel                   */
/***********************************************/

struct chanInfo*
get_chanInfo(const char *channelname)
{
	return dict_find(registered_channels_dict, channelname, 0);
}

static void
spamserv_join_channel(struct chanNode *channel)
{
	struct mod_chanmode change;
	mod_chanmode_init(&change);
	change.argc = 1;
	change.args[0].mode = MODE_CHANOP;
	change.args[0].u.member = AddChannelUser(spamserv, channel);
	mod_chanmode_announce(spamserv, channel, &change);
}

static void
spamserv_part_channel(struct chanNode *channel, char *reason)
{
	/* we only have to clear the spamNodes because every other node expires on it's own */
	spamserv_clear_spamNodes(channel);
	DelChannelUser(spamserv, channel, reason, 0);
}

static struct chanInfo*
spamserv_register_channel(struct chanNode *channel, struct string_list *exceptions, struct string_list *badwords, unsigned int flags, char *info)
{
	struct chanInfo *cInfo = malloc(sizeof(struct chanInfo));
	
	if(!cInfo)
	{
		log_module(SS_LOG, LOG_ERROR, "Couldn't allocate memory for cInfo; channel: %s", channel->name);
		return NULL;
	}

	cInfo->channel = channel;
	cInfo->exceptions = exceptions ? string_list_copy(exceptions) : alloc_string_list(1);
	cInfo->badwords = badwords ? string_list_copy(badwords) : alloc_string_list(1);
	cInfo->flags = flags;
	cInfo->exceptlevel = 300;
	safestrncpy(cInfo->info, info, sizeof(cInfo->info));
	cInfo->suspend_expiry = 0;
	dict_insert(registered_channels_dict, strdup(cInfo->channel->name), cInfo);

	return cInfo;
}

static void
spamserv_unregister_channel(struct chanInfo *cInfo)
{
	if(!cInfo)
		return;

	free_string_list(cInfo->exceptions);
	free_string_list(cInfo->badwords);
	dict_remove(registered_channels_dict, cInfo->channel->name);
	free(cInfo);
}

void
spamserv_cs_suspend(struct chanNode *channel, time_t expiry, int suspend, char *reason)
{
	struct chanInfo *cInfo = get_chanInfo(channel->name);

	if(cInfo)
	{
		if(suspend)
		{
			cInfo->flags |= CHAN_SUSPENDED;
			cInfo->suspend_expiry = expiry;
			spamserv_part_channel(channel, reason);
		}
		else
		{
			if(CHECK_SUSPENDED(cInfo))
			{
				cInfo->flags &= ~CHAN_SUSPENDED;
				cInfo->suspend_expiry = 0;
			}
		}
	}
}

int
spamserv_cs_move_merge(struct userNode *user, struct chanNode *channel, struct chanNode *target, int move)
{
	struct chanInfo *cInfo = get_chanInfo(channel->name);

	if(cInfo)
	{
		char reason[MAXLEN];

		if(!spamserv_conf.allow_move_merge || get_chanInfo(target->name))
		{
			if(move)
				snprintf(reason, sizeof(reason), "unregistered due to a channel move to %s", target->name);
			else
				snprintf(reason, sizeof(reason), "unregistered due to a channel merge into %s", target->name);

			spamserv_cs_unregister(user, channel, manually, reason);
			return 0;
		}

		cInfo->channel = target;

		dict_remove(registered_channels_dict, channel->name);
		dict_insert(registered_channels_dict, strdup(target->name), cInfo);

		if(move)
		{
			snprintf(reason, sizeof(reason), "Channel moved to %s by %s.", target->name, user->handle_info->handle);
		}
		else
		{
			spamserv_join_channel(target);
			snprintf(reason, sizeof(reason), "%s merged into %s by %s.", channel->name, target->name, user->handle_info->handle);	
		}

		if(!CHECK_SUSPENDED(cInfo))
			spamserv_part_channel(channel, reason);

		if(move)
			global_message_args(MESSAGE_RECIPIENT_OPERS | MESSAGE_RECIPIENT_HELPERS, 
                                            "SSMSG_CHANNEL_MOVED", channel->name, target->name, 
                                            user->handle_info->handle);
		else
			global_message_args(MESSAGE_RECIPIENT_OPERS | MESSAGE_RECIPIENT_HELPERS, 
                                            "SSMSG_CHANNEL_MERGED", channel->name, target->name, 
                                            user->handle_info->handle);

		return 1;
	}

	return 0;
}

void
spamserv_cs_unregister(struct userNode *user, struct chanNode *channel, enum cs_unreg type, char *reason)
{
	struct chanInfo *cInfo = get_chanInfo(channel->name);

	if(cInfo)
	{
		char partmsg[MAXLEN];

		switch (type)
		{
		case manually:
 			global_message_args(MESSAGE_RECIPIENT_OPERS | MESSAGE_RECIPIENT_HELPERS, "SSMSG_UNREG_MANUAL",
					    channel->name, reason, user->handle_info->handle);
			snprintf(partmsg, sizeof(partmsg), "%s %s by %s.", channel->name, reason, user->handle_info->handle);			
			break;
		case expire:
			global_message_args(MESSAGE_RECIPIENT_OPERS | MESSAGE_RECIPIENT_HELPERS, "SSMSG_REG_EXPIRED",
				            channel->name);
			snprintf(partmsg, sizeof(partmsg), "%s registration expired.", channel->name);			
			break;
		case lost_all_users:
			global_message_args(MESSAGE_RECIPIENT_OPERS | MESSAGE_RECIPIENT_HELPERS, "SSMSG_LOST_ALL_USERS",
				            channel->name);
			snprintf(partmsg, sizeof(partmsg), "%s lost all users.", channel->name);			
			break;
		}

		if(!CHECK_SUSPENDED(cInfo))
			spamserv_part_channel(channel, partmsg);
		
		spamserv_unregister_channel(cInfo);
	}
}

/***********************************************/
/*                    User                     */
/***********************************************/

static struct userInfo*
get_userInfo(const char *nickname)
{
	return dict_find(connected_users_dict, nickname, 0);
}

static void
spamserv_create_spamNode(struct chanNode *channel, struct userInfo *uInfo, char *text)
{
	struct spamNode *sNode = malloc(sizeof(struct spamNode));

	if(!sNode)
	{
		log_module(SS_LOG, LOG_ERROR, "Couldn't allocate memory for sNode; channel: %s; user: %s", channel->name, uInfo->user->nick);
		return;
	}

	sNode->channel = channel;	
	sNode->crc32 = crc32(text);
	sNode->count = 1;
	sNode->next = NULL;

	if(uInfo->spam)
	{
		struct spamNode *temp = uInfo->spam;
		
		while(temp->next)
			temp = temp->next;

		sNode->prev = temp;
		temp->next = sNode;
	}
	else
	{
		sNode->prev = NULL;
		uInfo->spam = sNode;
	}
}

static void
spamserv_delete_spamNode(struct userInfo *uInfo, struct spamNode *sNode)
{
	if(!sNode)
		return;

	if(sNode == uInfo->spam)
		uInfo->spam = sNode->next;
	
	if(sNode->next)
		 sNode->next->prev = sNode->prev;
	if(sNode->prev)
		 sNode->prev->next = sNode->next;

	free(sNode);
}

static void
spamserv_clear_spamNodes(struct chanNode *channel)
{
	struct userInfo *uInfo;
	struct spamNode *sNode;
	unsigned int i;

	for(i = 0; i < channel->members.used; i++)
	{
		if((uInfo = get_userInfo(channel->members.list[i]->user->nick)))
		{
			if((sNode = uInfo->spam))
			{
				for(; sNode; sNode = sNode->next)
					if(sNode->channel == channel)
						break;
					
				if(sNode)
					spamserv_delete_spamNode(uInfo, sNode);
			}
		}
	}
}

static void
spamserv_create_floodNode(struct chanNode *channel, struct userNode *user, struct floodNode **uI_fNode)
{
	struct floodNode *fNode = malloc(sizeof(struct floodNode));

	if(!fNode)
	{
		log_module(SS_LOG, LOG_ERROR, "Couldn't allocate memory for fNode; channel: %s; user: %s", channel->name, user->nick);
		return;
	}

	fNode->channel = channel;
	fNode->owner = user;
	fNode->count = 1;
	fNode->time = now;	
	fNode->next = NULL;

	if(*uI_fNode)
	{
		struct floodNode *temp = *uI_fNode;
		
		while(temp->next)
			temp = temp->next;
		
		fNode->prev = temp;
		temp->next = fNode;
	}
	else
	{
		fNode->prev = NULL;
		*uI_fNode = fNode;
	}
}

static void
spamserv_delete_floodNode(struct floodNode **uI_fNode, struct floodNode *fNode)
{
	if(!fNode)
		return;

	if(fNode == *uI_fNode)
		*uI_fNode = fNode->next;
	
	if(fNode->next)
		 fNode->next->prev = fNode->prev;
	if(fNode->prev)
		 fNode->prev->next = fNode->next;

	free(fNode);
}

static void
spamserv_create_user(struct userNode *user)
{
	struct userInfo *uInfo = malloc(sizeof(struct userInfo));
	struct killNode *kNode = dict_find(killed_users_dict, irc_ntoa(&user->ip), 0);

	if(!uInfo)
	{
		log_module(SS_LOG, LOG_ERROR, "Couldn't allocate memory for uInfo; nick: %s", user->nick);
		return;
	}

	if(kNode)
		spamserv_debug(SSMSG_DEBUG_RECONNECT, user->nick);

	uInfo->user = user;
	uInfo->spam = NULL;
	uInfo->flood = NULL;
	uInfo->joinflood = NULL;
	uInfo->flags = kNode ? USER_KILLED : 0;
	uInfo->warnlevel = kNode ? kNode->warnlevel : 0;
	uInfo->lastadv = 0;
	uInfo->lastbad = 0;

	dict_insert(connected_users_dict, strdup(user->nick), uInfo);

	if(kNode)
	{
		dict_remove(killed_users_dict, irc_ntoa(&user->ip));
		free(kNode);
	}
}

static void
spamserv_delete_user(struct userInfo *uInfo)
{
	if(!uInfo)
		return;

	if(uInfo->spam)
		while(uInfo->spam)
			spamserv_delete_spamNode(uInfo, uInfo->spam);	

	if(uInfo->flood)
		while(uInfo->flood)
			spamserv_delete_floodNode(&uInfo->flood, uInfo->flood);

	if(uInfo->joinflood)
		while(uInfo->joinflood)
			spamserv_delete_floodNode(&uInfo->joinflood, uInfo->joinflood);

	dict_remove(connected_users_dict, uInfo->user->nick);
	free(uInfo);
}

static int
spamserv_new_user_func(struct userNode *user)
{
	if(!IsLocal(user))
		spamserv_create_user(user);
  
	return 0;
}

static void
spamserv_del_user_func(struct userNode *user, struct userNode *killer, UNUSED_ARG(const char *why))
{
	struct userInfo *uInfo = get_userInfo(user->nick);
	struct killNode *kNode;

	if(killer == spamserv)
	{
		kNode = malloc(sizeof(struct killNode));

		if(!kNode)
		{
			log_module(SS_LOG, LOG_ERROR, "Couldn't allocate memory for killNode - nickname %s", user->nick);
			spamserv_delete_user(uInfo);			
			return;
		}

		if(uInfo->warnlevel > KILL_WARNLEVEL)
			kNode->warnlevel = uInfo->warnlevel - KILL_WARNLEVEL;
		else
			kNode->warnlevel = 0;

		kNode->time = now;

		dict_insert(killed_users_dict, strdup(irc_ntoa(&user->ip)), kNode);
	}

	spamserv_delete_user(uInfo);	
}

static void
spamserv_nick_change_func(struct userNode *user, const char *old_nick)
{
	struct userInfo *uInfo = get_userInfo(old_nick);

        if(uInfo) {
            dict_remove(connected_users_dict, old_nick);
            dict_insert(connected_users_dict, strdup(user->nick), uInfo);
        }
}

static int
spamserv_user_join(struct modeNode *mNode)
{
	struct chanNode	*channel = mNode->channel;
	struct userNode	*user = mNode->user;    
	struct chanInfo	*cInfo;
	struct userInfo	*uInfo;
	struct floodNode *jfNode;

	if(user->uplink->burst || !(cInfo = get_chanInfo(channel->name)) || !CHECK_JOINFLOOD(cInfo) || !(uInfo = get_userInfo(user->nick)))
		return 0;

	if(!(jfNode = uInfo->joinflood))
	{
		spamserv_create_floodNode(channel, user, &uInfo->joinflood);
	}
	else
	{
		for(; jfNode; jfNode = jfNode->next)
			if(jfNode->channel == channel)
				break;

		if(!jfNode)
		{
			spamserv_create_floodNode(channel, user, &uInfo->joinflood);
		}
		else
		{
			jfNode->count++;
			jfNode->time = now;		

			if(jfNode->count > JOINFLOOD_MAX)
			{
				char reason[MAXLEN];

				spamserv_delete_floodNode(&uInfo->joinflood, jfNode);
				snprintf(reason, sizeof(reason), spamserv_conf.network_rules ? SSMSG_WARNING_RULES : SSMSG_WARNING, SSMSG_JOINFLOOD, spamserv_conf.network_rules);
				spamserv_punish(channel, user, JOINFLOOD_B_DURATION, reason, 1);
			}
		}
	}

	return 0;
}

static void
spamserv_user_part(struct modeNode *mn, UNUSED_ARG(const char *reason))
{
	struct userNode *user = mn->user;
	struct chanNode *channel = mn->channel;
	struct userInfo *uInfo;
	struct spamNode *sNode;
	struct floodNode *fNode;

	if(user->dead || !get_chanInfo(channel->name) || !(uInfo = get_userInfo(user->nick)))
		return;

	if((sNode = uInfo->spam))
	{
		for(; sNode; sNode = sNode->next)
			if(sNode->channel == channel)
				break;

		if(sNode)
			spamserv_delete_spamNode(uInfo, sNode);
	}

	if((fNode = uInfo->flood))
	{
		for(; fNode; fNode = fNode->next)
			if(fNode->channel == channel)
				break;

		if(fNode)
			spamserv_delete_floodNode(&uInfo->flood, fNode);
	}
}

/***********************************************/
/*                 Other Stuff                 */
/***********************************************/

static void
crc32_init(void)
{
	unsigned long crc;
	int i, j;

	for(i = 0; i < 256; i++)
	{
		crc = i;

		for(j = 8; j > 0; j--)
		{
			if(crc & 1)
			{
				crc = (crc >> 1) ^ 0xEDB88320L;
			}
			else
			{
				crc >>= 1;
			}
		}

		crc_table[i] = crc;
	}
}

static unsigned long
crc32(const char *text)
{
	register unsigned long crc = 0xFFFFFFFF;
	unsigned int c, i = 0;
	
	while((c = (unsigned int)text[i++]) != 0)
		crc = ((crc >> 8) & 0x00FFFFFF) ^ crc_table[(crc^c) & 0xFF];
 
	return (crc^0xFFFFFFFF);
}

static void
timeq_flood(UNUSED_ARG(void *data))
{
	dict_iterator_t		it;
	struct userInfo		*uInfo;
	struct floodNode	*fNode;

	for(it = dict_first(connected_users_dict); it; it = iter_next(it))
	{
		uInfo = iter_data(it);

                if (!uInfo)
                    continue;

		if(!(fNode = uInfo->flood))
			continue;

		for(; fNode; fNode = fNode->next)
		{
			if(now - fNode->time > FLOOD_EXPIRE)
			{
				if(!(--fNode->count))
					spamserv_delete_floodNode(&uInfo->flood, fNode);
			}
		}
	}
	
	timeq_add(now + FLOOD_TIMEQ_FREQ, timeq_flood, NULL);
}

static void
timeq_joinflood(UNUSED_ARG(void *data))
{
	dict_iterator_t it;
	struct userInfo *uInfo;
	struct floodNode *fNode, *nextnode;

	for(it = dict_first(connected_users_dict); it; it = iter_next(it))
	{
		uInfo = iter_data(it);

		if(!(fNode = uInfo->joinflood))
			continue;

		for(; fNode; fNode = nextnode)
		{
                        nextnode = fNode->next;
			if(now - fNode->time > JOINFLOOD_EXPIRE)
			{
				if(!(--fNode->count))
					spamserv_delete_floodNode(&uInfo->joinflood, fNode);				
			}
		}
	}

	timeq_add(now + JOINFLOOD_TIMEQ_FREQ, timeq_joinflood, NULL);
}

static void
timeq_bad(UNUSED_ARG(void *data))
{
	dict_iterator_t it;
	struct userInfo *uInfo;

	for(it = dict_first(connected_users_dict); it; it = iter_next(it))
	{
		uInfo = iter_data(it);

		if(uInfo->lastbad && uInfo->lastbad - now > BAD_EXPIRE)
		{
			uInfo->lastbad = 0;
			uInfo->flags &= ~USER_BAD_WARNED;
		}
	}

	timeq_add(now + BAD_TIMEQ_FREQ, timeq_bad, NULL);
}

static void
timeq_adv(UNUSED_ARG(void *data))
{
	dict_iterator_t it;
	struct userInfo *uInfo;

	for(it = dict_first(connected_users_dict); it; it = iter_next(it))
	{
		uInfo = iter_data(it);

		if(uInfo->lastadv && uInfo->lastadv - now > ADV_EXPIRE)
		{
			uInfo->lastadv = 0;
			uInfo->flags &= ~USER_ADV_WARNED;
		}
	}

	timeq_add(now + ADV_TIMEQ_FREQ, timeq_adv, NULL);
}

static void
timeq_warnlevel(UNUSED_ARG(void *data))
{
	dict_iterator_t it;
	struct userInfo *uInfo;

	for(it = dict_first(connected_users_dict); it; it = iter_next(it))
	{
		uInfo = iter_data(it);

		if(uInfo->warnlevel > 0)
			uInfo->warnlevel--;
	}

	timeq_add(now + WARNLEVEL_TIMEQ_FREQ, timeq_warnlevel, NULL);
}

static void
timeq_kill(UNUSED_ARG(void *data))
{
	dict_iterator_t it;
	struct killNode *kNode;

        while(1) {
            for(it = dict_first(killed_users_dict); it; it = iter_next(it))
            {
                    kNode = iter_data(it);

                    if(now - kNode->time > KILL_EXPIRE) {
                            dict_remove(killed_users_dict, iter_key(it));
                             /* have to restart the loop because next is
                              * now invalid. FIXME: how could we do this better? */
                             break; /* out of for() loop */
                    }
            }
            /* no more killed_users to delete, so stop while loop */
            break; /* out of while() loop */ 
        }

	timeq_add(now + KILL_TIMEQ_FREQ, timeq_kill, NULL);
}

static int
binary_option(char *name, unsigned long mask, struct userNode *user, struct chanNode *channel, int argc, char *argv[])
{
	struct chanInfo *cInfo = get_chanInfo(channel->name);
	int value;

	if(argc > 1)
	{
		if(enabled_string(argv[1]))
		{
			cInfo->flags |= mask;
			value = 1;
		}
		else if(disabled_string(argv[1]))
		{
		    cInfo->flags &= ~mask;
		    value = 0;
		}
		else
		{
		   spamserv_notice(user, "SSMSG_INVALID_BINARY", argv[1]);
		   return 0;
		}
	}
	else
	{
		value = (cInfo->flags & mask) ? 1 : 0;
	}

	spamserv_notice(user, "SSMSG_STRING_VALUE", name, value ? "Enabled." : "Disabled.");
	return 1;
}

struct valueData
{
	char *description;
	char value;
	int  oper_only : 1;
};

static int
multiple_option(char *name, char *description, enum channelinfo info, struct valueData *values, int count, struct userNode *user, struct chanNode *channel, int argc, char *argv[])
{
	struct chanInfo *cInfo = get_chanInfo(channel->name);
	int index;

	if(argc > 1)
	{
		index = atoi(argv[1]);
		
		if(index < 0 || index >= count)
		{
			spamserv_notice(user, "SSMSG_INVALID_NUM_SET", index, description);

            for(index = 0; index < count; index++)
                spamserv_notice(user, "SSMSG_NUMERIC_VALUE", name, index, values[index].description);

			return 0;
		}

		if(values[index].oper_only && !IsOper(user))
		{
			spamserv_notice(user, "SSMSG_MUST_BE_OPER");
			return 0;
		}
		
		cInfo->info[info] = values[index].value;
	}
	else
	{
		for(index = 0; index < count && cInfo->info[info] != values[index].value; index++);
	}

	spamserv_notice(user, "SSMSG_NUMERIC_VALUE", name, index, values[index].description);
	return 1;
}

static int
show_exceptions(struct userNode *user, struct chanInfo *cInfo)
{
	struct helpfile_table table;
	unsigned int i;

	if(!cInfo->exceptions->used)
	{
		spamserv_notice(user, "SSMSG_NO_EXCEPTIONS");
		return 0;
	}

	spamserv_notice(user, "SSMSG_EXCEPTION_LIST");

	table.length = 0;
	table.width = 1;
	table.flags = TABLE_REPEAT_ROWS | TABLE_NO_FREE | TABLE_NO_HEADERS;
	table.contents = alloca(cInfo->exceptions->used * sizeof(*table.contents));

	for(i = 0; i < cInfo->exceptions->used; i++)
	{
		table.contents[table.length] = alloca(table.width * sizeof(**table.contents));
		table.contents[table.length][0] = cInfo->exceptions->list[i];
		table.length++;
	}
	
	table_send(spamserv, user->nick, 0, NULL, table);

	return 1;
}

static int
show_badwords(struct userNode *user, struct chanInfo *cInfo)
{
	struct helpfile_table table;
	unsigned int i;

	if(!cInfo->badwords->used)
	{
		spamserv_notice(user, "SSMSG_NO_BADWORDS");
		return 0;
	}

	spamserv_notice(user, "SSMSG_BADWORD_LIST");

	table.length = 0;
	table.width = 1;
	table.flags = TABLE_REPEAT_ROWS | TABLE_NO_FREE | TABLE_NO_HEADERS;
	table.contents = alloca(cInfo->badwords->used * sizeof(*table.contents));

	for(i = 0; i < cInfo->badwords->used; i++)
	{
		table.contents[table.length] = alloca(table.width * sizeof(**table.contents));
		table.contents[table.length][0] = cInfo->badwords->list[i];
		table.length++;
	}
	
	table_send(spamserv, user->nick, 0, NULL, table);

	return 1;
}

static void
show_memory_usage(struct userNode *user)
{
	dict_iterator_t it;
	struct helpfile_table table;
	struct chanInfo *cInfo;
	struct userInfo *uInfo;
	struct spamNode *sNode;
	struct floodNode *fNode;
	double channel_size = 0, user_size, size;
	unsigned int spamcount = 0, floodcount = 0, i, j;
	char buffer[64];

	for(it = dict_first(registered_channels_dict); it; it = iter_next(it))
	{
		cInfo = iter_data(it);

		if(!cInfo->exceptions->used)
			continue;

		if(!cInfo->badwords->used)
			continue;

		for(i = 0; i < cInfo->exceptions->used; i++)
			channel_size += strlen(cInfo->exceptions->list[i]) * sizeof(char);		

		for(i = 0; i < cInfo->badwords->used; i++)
			channel_size += strlen(cInfo->badwords->list[i]) * sizeof(char);		
	}

	for(it = dict_first(connected_users_dict); it; it = iter_next(it))
	{
		uInfo = iter_data(it);

		for(sNode = uInfo->spam; sNode; sNode = sNode->next, spamcount++);
		for(fNode = uInfo->flood; fNode; fNode = fNode->next, floodcount++);
		for(fNode = uInfo->joinflood; fNode; fNode = fNode->next, floodcount++);
	}

	channel_size += dict_size(registered_channels_dict) * sizeof(struct chanInfo);
	
	user_size = dict_size(connected_users_dict) * sizeof(struct userInfo) +
				dict_size(killed_users_dict) * sizeof(struct killNode) +
				spamcount * sizeof(struct spamNode)	+
				floodcount *  sizeof(struct floodNode);

	size = channel_size + user_size;
	
	ss_reply("SSMSG_STATUS_MEMORY");
	
	table.length = 3;
	table.width = 4;
	table.flags = TABLE_NO_FREE | TABLE_NO_HEADERS | TABLE_PAD_LEFT;
	table.contents = calloc(table.length, sizeof(char**));

	// chanInfo
	table.contents[0] = calloc(table.width, sizeof(char*));
	snprintf(buffer, sizeof(buffer), "Channel Memory Usage:");
	table.contents[0][0] = strdup(buffer);
	snprintf(buffer, sizeof(buffer), " %g Byte; ", channel_size);
	table.contents[0][1] = strdup(buffer);
	snprintf(buffer, sizeof(buffer), "%g KiloByte; ", channel_size / 1024);
	table.contents[0][2] = strdup(buffer);
	snprintf(buffer, sizeof(buffer), "%g MegaByte", channel_size / 1024 / 1024);
	table.contents[0][3] = strdup(buffer);

	// userInfo
	table.contents[1] = calloc(table.width, sizeof(char*));
	snprintf(buffer, sizeof(buffer), "User Memory Usage   :");
	table.contents[1][0] = strdup(buffer);
	snprintf(buffer, sizeof(buffer), " %g Byte; ", user_size);
	table.contents[1][1] = strdup(buffer);
	snprintf(buffer, sizeof(buffer), "%g KiloByte; ", user_size / 1024);
	table.contents[1][2] = strdup(buffer);
	snprintf(buffer, sizeof(buffer), "%g MegaByte", user_size / 1024 / 1024);
	table.contents[1][3] = strdup(buffer);

	// total memory usage
	table.contents[2] = calloc(table.width, sizeof(char*));
	snprintf(buffer, sizeof(buffer), "Total Memory Usage  :");
	table.contents[2][0] = strdup(buffer);
	snprintf(buffer, sizeof(buffer), " %g Byte; ", size);
	table.contents[2][1] = strdup(buffer);
	snprintf(buffer, sizeof(buffer), "%g KiloByte; ", size / 1024);
	table.contents[2][2] = strdup(buffer);
	snprintf(buffer, sizeof(buffer), "%g MegaByte", size / 1024 / 1024);
	table.contents[2][3] = strdup(buffer);

	table_send(spamserv, user->nick, 0, NULL, table);
	
	for(i = 0; i < table.length; i++)
	{
		for(j = 0; j < table.width; j++)
			free((char*)table.contents[i][j]);

        free(table.contents[i]);
	}

	free(table.contents);
}

static void
show_registered_channels(struct userNode *user)
{
	struct helpfile_table table;
	dict_iterator_t it;

	spamserv_notice(user, "SSMSG_STATUS_CHANNEL_LIST");

	if(!dict_size(registered_channels_dict))
	{
		spamserv_notice(user, "SSMSG_STATUS_NO_CHANNEL");
		return;
	}

	table.length = 0;
	table.width = 1;
	table.flags = TABLE_REPEAT_ROWS | TABLE_NO_FREE | TABLE_NO_HEADERS;
	table.contents = alloca(dict_size(registered_channels_dict) * sizeof(*table.contents));

	for(it = dict_first(registered_channels_dict); it; it = iter_next(it))
	{
		struct chanInfo *cInfo = iter_data(it);

		table.contents[table.length] = alloca(table.width * sizeof(**table.contents));
		table.contents[table.length][0] = cInfo->channel->name;
		table.length++;
	}
	
	table_send(spamserv, user->nick, 0, NULL, table);
}

/***********************************************/
/*                SpamServ_Func                */
/***********************************************/

static 
SPAMSERV_FUNC(cmd_register)
{
	struct chanInfo *cInfo;

	if(!channel || !channel->channel_info)
	{
		ss_reply("SSMSG_NOT_REGISTERED_CS", channel->name);
		return 0;
	}

	if(get_chanInfo(channel->name))
	{
		ss_reply("SSMSG_ALREADY_REGISTERED", channel->name);
		return 0;
	}

	if(IsSuspended(channel->channel_info))
	{
		ss_reply("SSMSG_SUSPENDED_CS", channel->name, "register");
		return 0;
	}

	if(channel == spamserv_conf.debug_channel)
	{
		ss_reply("SSMSG_DEBUG_CHAN");
		return 0;
	}

	if(!(cInfo = spamserv_register_channel(channel, spamserv_conf.global_exceptions, spamserv_conf.global_badwords, CHAN_FLAGS_DEFAULT , CHAN_INFO_DEFAULT)))
	{
		ss_reply("SSMSG_NO_REGISTER", channel->name);
		return 0;
	}

	spamserv_join_channel(cInfo->channel);
	
	global_message_args(MESSAGE_RECIPIENT_OPERS | MESSAGE_RECIPIENT_HELPERS, "SSMSG_REGISTERED_BY",
			    channel->name, user->handle_info->handle);
	ss_reply("SSMSG_REG_SUCCESS", channel->name);

	return 1;
}

static 
SPAMSERV_FUNC(cmd_unregister)
{
	struct chanInfo *cInfo;
	struct chanData *cData;
	struct userData *uData;
	char reason[MAXLEN];

	if(!channel || !(cData = channel->channel_info) || !(cInfo = get_chanInfo(channel->name)))
	{
		ss_reply("SSMSG_NOT_REGISTERED", channel->name);
		return 0;
	}

	if(!(uData = GetChannelUser(cData, user->handle_info)) || (uData->access < UL_OWNER))
	{
        ss_reply("SSMSG_NO_ACCESS");
        return 0;
	}

	if(!IsHelping(user))
	{
        if(IsSuspended(cData))
        {
            ss_reply("SSMSG_SUSPENDED_CS", channel->name, "unregister");
            return 0;
        }

		if(argc < 2 || strcasecmp(argv[1], "CONFIRM"))
		{
			ss_reply("SSMSG_CONFIRM_UNREG");
			return 0;
		}
        }

	if(!CHECK_SUSPENDED(cInfo))
	{
		snprintf(reason, sizeof(reason), "%s unregistered by %s.", spamserv->nick, user->handle_info->handle);		
		spamserv_part_channel(channel, reason);
	}
	
	spamserv_unregister_channel(cInfo);	

	global_message_args(MESSAGE_RECIPIENT_OPERS | MESSAGE_RECIPIENT_HELPERS, "SSMSG_UNREGISTERED_BY",
			    channel->name, user->handle_info->handle);
	ss_reply("SSMSG_UNREG_SUCCESS", channel->name);

	return 1;
}

static 
SPAMSERV_FUNC(cmd_status)
{
	ss_reply("SSMSG_STATUS");
	ss_reply("SSMSG_STATUS_USERS", dict_size(connected_users_dict));
	ss_reply("SSMSG_STATUS_CHANNELS", dict_size(registered_channels_dict));

	if(IsOper(user) && argc > 1)
	{
		if(!irccasecmp(argv[1], "memory"))
			show_memory_usage(user);
		else if(!irccasecmp(argv[1], "channels"))
			show_registered_channels(user);		
	}
	
	return 1;
}

static 
SPAMSERV_FUNC(cmd_addexception)
{
	struct chanInfo *cInfo = get_chanInfo(channel->name);
	struct userData *uData;
	unsigned int i;

	if(!cInfo || !channel->channel_info)
	{
		ss_reply("SSMSG_NOT_REGISTERED", channel->name);
		return 0;
	}

	if(CHECK_SUSPENDED(cInfo))
	{
		ss_reply("SSMSG_SUSPENDED", channel->name);
		return 0;
	}

	if(!(uData = GetChannelUser(channel->channel_info, user->handle_info)) || (uData->access < 400))
	{
		ss_reply("SSMSG_NO_ACCESS");
		return 0;
	}

	if(argc < 2)
		return show_exceptions(user, cInfo);

	if(cInfo->exceptions->used == spamserv_conf.exception_max && !IsOper(user))
	{
		ss_reply("SSMSG_EXCEPTION_MAX", spamserv_conf.exception_max);
		return 0;
	}

	if(strlen(argv[1]) < spamserv_conf.exception_min_len)
	{
		ss_reply("SSMSG_EXCEPTION_TOO_SHORT", spamserv_conf.exception_min_len);
		return 0;
	}
	else if(strlen(argv[1]) > spamserv_conf.exception_max_len)
	{
		ss_reply("SSMSG_EXCEPTION_TOO_LONG", spamserv_conf.exception_max_len);
		return 0;
	}

	for(i = 0; i < cInfo->exceptions->used; i++)
	{
		if(!irccasecmp(argv[1], cInfo->exceptions->list[i]))
		{
			ss_reply("SSMSG_EXCEPTION_IN_LIST", argv[1]);
			return 0;
		}
	}

	string_list_append(cInfo->exceptions, strdup(argv[1]));
	ss_reply("SSMSG_EXCEPTION_ADDED", argv[1]);

	return 1;
}

static 
SPAMSERV_FUNC(cmd_delexception)
{
	struct chanInfo *cInfo = get_chanInfo(channel->name);
	struct userData *uData;
	unsigned int i;
	int found = -1;

	if(!cInfo || !channel->channel_info)
	{
		ss_reply("SSMSG_NOT_REGISTERED", channel->name);
		return 0;
	}

	if(CHECK_SUSPENDED(cInfo))
	{
		ss_reply("SSMSG_SUSPENDED", channel->name);
		return 0;
	}

	if(!(uData = GetChannelUser(channel->channel_info, user->handle_info)) || (uData->access < 400))
	{
		ss_reply("SSMSG_NO_ACCESS");
		return 0;
	}

	if(argc < 2)
		return show_exceptions(user, cInfo);

	for(i = 0; i < cInfo->exceptions->used; i++)
	{
		if(!irccasecmp(argv[1], cInfo->exceptions->list[i]))
		{
			found = i;
			break;
		}
	}
	
	if(found == -1)
	{
		ss_reply("SSMSG_NO_SUCH_EXCEPTION", argv[1]);
		return 0;
	}

	string_list_delete(cInfo->exceptions, i);
	ss_reply("SSMSG_EXCEPTION_DELETED", argv[1]);

	return 1;
}

static 
SPAMSERV_FUNC(cmd_addbadword)
{
	struct chanInfo *cInfo = get_chanInfo(channel->name);
	struct userData *uData;
	unsigned int i;

	if(!cInfo || !channel->channel_info)
	{
		ss_reply("SSMSG_NOT_REGISTERED", channel->name);
		return 0;
	}

	if(CHECK_SUSPENDED(cInfo))
	{
		ss_reply("SSMSG_SUSPENDED", channel->name);
		return 0;
	}

	if(!(uData = GetChannelUser(channel->channel_info, user->handle_info)) || (uData->access < 400))
	{
		ss_reply("SSMSG_NO_ACCESS");
		return 0;
	}

	if(argc < 2)
		return show_badwords(user, cInfo);

	if(cInfo->badwords->used == spamserv_conf.badword_max && !IsOper(user))
	{
		ss_reply("SSMSG_BADWORD_MAX", spamserv_conf.badword_max);
		return 0;
	}

	if(strlen(argv[1]) < spamserv_conf.badword_min_len)
	{
		ss_reply("SSMSG_BADWORD_TOO_SHORT", spamserv_conf.badword_min_len);
		return 0;
	}
	else if(strlen(argv[1]) > spamserv_conf.badword_max_len)
	{
		ss_reply("SSMSG_BADWORD_TOO_LONG", spamserv_conf.badword_max_len);
		return 0;
	}

	for(i = 0; i < cInfo->badwords->used; i++)
	{
		if(!irccasecmp(argv[1], cInfo->badwords->list[i]))
		{
			ss_reply("SSMSG_BADWORD_IN_LIST", argv[1]);
			return 0;
		}
	}

	string_list_append(cInfo->badwords, strdup(argv[1]));
	ss_reply("SSMSG_BADWORD_ADDED", argv[1]);

	return 1;
}

static 
SPAMSERV_FUNC(cmd_delbadword)
{
	struct chanInfo *cInfo = get_chanInfo(channel->name);
	struct userData *uData;
	unsigned int i;
	int found = -1;

	if(!cInfo || !channel->channel_info)
	{
		ss_reply("SSMSG_NOT_REGISTERED", channel->name);
		return 0;
	}

	if(CHECK_SUSPENDED(cInfo))
	{
		ss_reply("SSMSG_SUSPENDED", channel->name);
		return 0;
	}

	if(!(uData = GetChannelUser(channel->channel_info, user->handle_info)) || (uData->access < 400))
	{
		ss_reply("SSMSG_NO_ACCESS");
		return 0;
	}

	if(argc < 2)
		return show_badwords(user, cInfo);

	for(i = 0; i < cInfo->badwords->used; i++)
	{
		if(!irccasecmp(argv[1], cInfo->badwords->list[i]))
		{
			found = i;
			break;
		}
	}
	
	if(found == -1)
	{
		ss_reply("SSMSG_NO_SUCH_BADWORD", argv[1]);
		return 0;
	}

	string_list_delete(cInfo->badwords, i);
	ss_reply("SSMSG_BADWORD_DELETED", argv[1]);

	return 1;
}

static 
SPAMSERV_FUNC(cmd_set)
{
	struct chanInfo *cInfo = get_chanInfo(channel->name);
	struct userData *uData;
	struct svccmd	*subcmd;	
	char cmd_name[MAXLEN];
	unsigned int i;

	if(!cInfo)
	{
		ss_reply("SSMSG_NOT_REGISTERED", channel->name);
		return 0;
	}

	if(CHECK_SUSPENDED(cInfo))
	{
		ss_reply("SSMSG_SUSPENDED", channel->name);
		return 0;
	}

	if(!(uData = GetChannelUser(channel->channel_info, user->handle_info)) || (uData->access < 400))
	{
		ss_reply("SSMSG_NO_ACCESS");
		return 0;
	}
	
	if(argc < 2)
	{
		ss_reply("SSMSG_CHANNEL_OPTIONS");

		for(i = 0; i < SET_SUBCMDS_SIZE; i++)
		{
			sprintf(cmd_name, "%s %s", cmd->name, set_subcommands[i]);

			if((subcmd = dict_find(cmd->parent->commands, cmd_name, NULL)))
				subcmd->command->func(user, channel, 1, argv + 1, subcmd);
		}

		return 1;
	}

	sprintf(cmd_name, "%s %s", cmd->name, argv[1]);
	subcmd = dict_find(cmd->parent->commands, cmd_name, NULL);

	if(!subcmd)
	{
		reply("SSMSG_INVALID_OPTION", argv[1], argv[0]);
		return 0;
	}

	return subcmd->command->func(user, channel, argc - 1, argv + 1, subcmd);
}

int ss_check_user_level(struct chanNode *channel, struct userNode *user, unsigned int minimum, int allow_override, int exempt_owner)
{
    struct userData *uData;
    struct chanData *cData = channel->channel_info;
    if(!minimum)
        return 1;
    uData = _GetChannelUser(cData, user->handle_info, allow_override, 0);
    if(!uData)
        return 0;
    if(minimum <= uData->access)
        return 1;
    if((minimum > UL_OWNER) && (uData->access == UL_OWNER) && exempt_owner)
        return 1;
    return 0;
}


static int
channel_except_level(struct userNode *user, struct chanNode *channel, int argc, char *argv[], struct svccmd *cmd)
{
    struct chanData *cData = channel->channel_info;
    struct chanInfo *cInfo;
    struct userData *uData;
    unsigned short value;

    cInfo = get_chanInfo(channel->name);

    if(argc > 1)
    {
        if(!ss_check_user_level(channel, user, cInfo->exceptlevel, 1, 1))
        {
            reply("SSMSG_CANNOT_SET");
            return 0;
        }
        value = user_level_from_name(argv[1], UL_OWNER+1);
        if(!value && strcmp(argv[1], "0"))
	{
	    reply("SSMSG_INVALID_ACCESS", argv[1]);
            return 0;
        }
        uData = GetChannelUser(cData, user->handle_info);
        if(!uData || ((uData->access < UL_OWNER) && (value > uData->access)))
        {
            reply("SSMSG_BAD_SETLEVEL");
            return 0;
        }
        cInfo->exceptlevel = value;
    }
    reply("SSMSG_SET_EXCEPTLEVEL", cInfo->exceptlevel);
    return 0;
}

static
SPAMSERV_FUNC(opt_exceptlevel)
{
    return channel_except_level(SSFUNC_ARGS);
}

static 
SPAMSERV_FUNC(opt_spamlimit)
{
	struct valueData values[] =
	{
		{"Users may send the same message $b2$b times.", 'a', 0},
		{"Users may send the same message $b3$b times.", 'b', 0},
		{"Users may send the same message $b4$b times.", 'c', 0},
		{"Users may send the same message $b5$b times.", 'd', 0},
		{"Users may send the same message $b6$b times.", 'e', 0}
	};

	MULTIPLE_OPTION("SpamLimit     ", "SpamLimit", ci_SpamLimit);
}

static 
SPAMSERV_FUNC(opt_advreaction)
{
	struct valueData values[] =
	{
		{"Kick on disallowed advertising.", 'k', 0},
		{"Kickban on disallowed advertising.", 'b', 0},
		{"Short timed ban on disallowed advertising.", 's', 0},
		{"Long timed ban on disallowed advertising.", 'l', 0},
		{"Kill on disallowed advertising.", 'd', 1}
	};

	MULTIPLE_OPTION("AdvReaction   ", "AdvReaction", ci_AdvReaction);
}

static 
SPAMSERV_FUNC(opt_warnreaction)
{
	struct valueData values[] =
	{
		{"Kick after warning.", 'k', 0},
		{"Kickban after warning.", 'b', 0},
		{"Short timed ban after warning.", 's', 0},
		{"Long timed ban after warning.", 'l', 0},
		{"Kill after warning.", 'd', 1}
	};

	MULTIPLE_OPTION("WarnReaction  ", "WarnReaction", ci_WarnReaction);
}

static 
SPAMSERV_FUNC(opt_badreaction)
{
	struct valueData values[] =
	{
		{"Kick on disallowed badwords.", 'k', 0},
		{"Kickban on disallowed badwords.", 'b', 0},
		{"Short timed ban on disallowed badwords.", 's', 0},
		{"Long timed ban on disallowed badwords.", 'l', 0},
		{"Kill on disallowed badwords.", 'd', 1}
	};

	MULTIPLE_OPTION("BadReaction   ", "BadReaction", ci_BadReaction);
}

static 
SPAMSERV_FUNC(opt_advscan)
{
	BINARY_OPTION("AdvScan       ", CHAN_ADV_SCAN);
}

static 
SPAMSERV_FUNC(opt_spamscan)
{
	BINARY_OPTION("SpamScan      ", CHAN_SPAMSCAN);
}

static 
SPAMSERV_FUNC(opt_badwordscan)
{
	BINARY_OPTION("BadWordScan   ", CHAN_BADWORDSCAN);
}

static 
SPAMSERV_FUNC(opt_chanfloodscan)
{
	BINARY_OPTION("ChanFloodScan ", CHAN_CHANFLOODSCAN);
}

static 
SPAMSERV_FUNC(opt_joinflood)
{
	BINARY_OPTION("JoinFloodScan ", CHAN_JOINFLOOD);
}

static 
SPAMSERV_FUNC(opt_scanops)
{
	BINARY_OPTION("ScanChanOps   ", CHAN_SCAN_CHANOPS);
}

static 
SPAMSERV_FUNC(opt_scanhalfops)
{
	BINARY_OPTION("ScanHalfOps   ", CHAN_SCAN_HALFOPS);
}

static 
SPAMSERV_FUNC(opt_scanvoiced)
{
	BINARY_OPTION("ScanVoiced    ", CHAN_SCAN_VOICED);
}

static void
spamserv_add_trusted_account(const char *account, struct string_list *channel, const char *issuer, time_t issued)
{
    struct trusted_account *ta;
    ta = calloc(1, sizeof(*ta));
    if (!ta)
        return;
    ta->account = strdup(account);
    ta->channel = channel ? string_list_copy(channel) : alloc_string_list(1);
    ta->issuer = strdup(issuer);
    ta->issued = issued;
    dict_insert(spamserv_trusted_accounts, strdup(ta->account), ta);
}

/*
static void
free_trusted_account(void *data)
{
    struct trusted_account *ta = data;
    free(ta->account);
    free_string_list(ta->channel);
    free(ta->issuer);
    free(ta);
}
*/

static SPAMSERV_FUNC(cmd_addtrust)
{
    unsigned int i;
    struct userData *uData;
    struct chanData *cData;
    struct chanInfo *cInfo;
    struct trusted_account *ta;
    struct string_list *templist;
    struct handle_info *hi;

    if (!(channel = GetChannel(argv[2]))) {
        ss_reply("SSMSG_NOT_REGISTERED", channel->name);
        return 0;
    }

    cInfo = get_chanInfo(channel->name);
    cData = channel->channel_info;
    uData = GetChannelUser(cData, user->handle_info);

    if (!cInfo || !channel->channel_info) {
        ss_reply("SSMSG_NOT_REGISTERED", channel->name);
        return 0;
    }

    if (CHECK_SUSPENDED(cInfo)) {
         ss_reply("SSMSG_SUSPENDED", channel->name);
         return 0;
    }

    if (!uData || (uData->access < UL_MANAGER)) {
        ss_reply("SSMSG_NO_ACCESS");
        return 0;
    }

    if (!(hi = modcmd_get_handle_info(user, argv[1]))) {
        return 0;
    }

    if ((ta = dict_find(spamserv_trusted_accounts, argv[1], NULL))) {
        if (ta->channel->used && (argc > 1)) {
            for (i=0; i < ta->channel->used; i++) {
                if (!strcmp(ta->channel->list[i], argv[2])) {
                    ss_reply("SSMSG_ALREADY_TRUSTED", hi->handle);
                    return 0;
                }
            }
        }

        string_list_append(ta->channel, argv[2]);
        ss_reply("SSMSG_ADDED_TRUSTED_CHANNEL", hi->handle, argv[2]);
        return 1;
    }

    templist = alloc_string_list(sizeof(argv[2])+1);
//    templist = alloc_string_list(1);
    string_list_append(templist, argv[2]);

    spamserv_add_trusted_account(hi->handle, templist, user->handle_info->handle, now);
    ss_reply("SSMSG_ADDED_TRUSTED_CHANNEL", hi->handle, argv[2]);
    return 1;
}

static SPAMSERV_FUNC(cmd_oaddtrust)
{
    unsigned int i, global = 0;
    struct chanInfo *cInfo;
    struct chanData *cData;
    struct trusted_account *ta;
    struct string_list *templist;
    struct handle_info *hi;

    if (!strcmp(argv[2], "global"))
        global = 1;

    if (!(channel = GetChannel(argv[2])) && (global == 0)) {
        ss_reply("SSMSG_NOT_REGISTERED", channel ? channel->name : (global ? "global" : ""));
        return 0;
    }

    if (channel) {
        cInfo = get_chanInfo(channel->name);
        cData = channel->channel_info;

        if (!cInfo || !channel->channel_info) {
            ss_reply("SSMSG_NOT_REGISTERED", channel->name);
            return 0;
        }
    }

    if (!(hi = modcmd_get_handle_info(user, argv[1]))) {
        return 0;
    }

    if ((ta = dict_find(spamserv_trusted_accounts, argv[1], NULL))) {
        if (ta->channel->used && (argc > 1)) {
            for (i=0; i < ta->channel->used; i++) {
                if (!strcmp(ta->channel->list[i], argv[2])) {
                    ss_reply("SSMSG_ALREADY_TRUSTED", argv[1]);
                    return 0;
                }
            }
        }

        string_list_append(ta->channel, argv[2]);

        if (global == 1)
            ss_reply("SSMSG_ADDED_TRUSTED", argv[1]);
        else
            ss_reply("SSMSG_ADDED_TRUSTED_CHANNEL", argv[1], argv[2]);

        return 1;
    }

    templist = alloc_string_list(sizeof(argv[2])+1);
//    templist = alloc_string_list(1);
    string_list_append(templist, argv[2]);

    spamserv_add_trusted_account(hi->handle, templist, user->handle_info->handle, now);

    if (global == 1)
        ss_reply("SSMSG_ADDED_TRUSTED", hi->handle);
    else
        ss_reply("SSMSG_ADDED_TRUSTED_CHANNEL", hi->handle, argv[2]);

    return 1;
}

static SPAMSERV_FUNC(cmd_deltrust)
{
    unsigned int i;
    int rem = 0;
    struct trusted_account *ta;
    struct userData *uData;
    struct chanData *cData;
    struct chanInfo *cInfo;
    struct handle_info *hi;

    if (!(channel = GetChannel(argv[2]))) {
        ss_reply("SSMSG_NOT_REGISTERED", channel->name);
        return 0;
    }

    cInfo = get_chanInfo(channel->name);
    cData = channel->channel_info;
    uData = GetChannelUser(cData, user->handle_info);

    if (!cInfo || !channel->channel_info) {
        ss_reply("SSMSG_NOT_REGISTERED", channel->name);
        return 0;
    }

    if (CHECK_SUSPENDED(cInfo)) {
         ss_reply("SSMSG_SUSPENDED", channel->name);
         return 0;
    }

    if (!uData || (uData->access < UL_MANAGER)) {
        ss_reply("SSMSG_NO_ACCESS");
        return 0;
    }

    if (!(hi = modcmd_get_handle_info(user, argv[1]))) {
        return 0;
    }

    ta = dict_find(spamserv_trusted_accounts, hi->handle, NULL);

    if (!ta) {
        ss_reply("SSMSG_NOT_TRUSTED", argv[2]);
        return 0;
    }

    if (argc > 1) {
        if (ta->channel->used) {
            for (i=0; i < ta->channel->used; i++) {
                if (!strcmp(ta->channel->list[i], argv[2])) {
                    string_list_delete(ta->channel, i);
                    rem = 1;
                }
            }
        }

        if (rem == 1)
            ss_reply("SSMSG_REMOVED_TRUSTED_CHANNEL", hi->handle, argv[2]);
        else {
            ss_reply("SSMSG_NOT_TRUSTED", hi->handle, argv[2]);
            return 0;
        }
    } else {
        dict_remove(spamserv_trusted_accounts, hi->handle);
        ss_reply("SSMSG_REMOVED_TRUSTED", hi->handle);
    }

    return 1;
}

static SPAMSERV_FUNC(cmd_odeltrust)
{
    unsigned int i;
    int rem = 0, global = 0;
    struct trusted_account *ta;
    struct chanInfo *cInfo;
    struct chanData *cData;
    struct handle_info *hi;

    if (!strcmp(argv[2], "global"))
        global = 1;

    if (!(channel = GetChannel(argv[2])) && (global == 0)) {
        ss_reply("SSMSG_NOT_REGISTERED", channel ? channel->name : (global ? "global" : ""));
        return 0;
    }

    if (channel) {
        cInfo = get_chanInfo(channel->name);
        cData = channel->channel_info;

        if (!cInfo || !channel->channel_info) {
            ss_reply("SSMSG_NOT_REGISTERED", channel->name);
            return 0;
        }
    }

    if (!(hi = modcmd_get_handle_info(user, argv[1]))) {
        return 0;
    }

    ta = dict_find(spamserv_trusted_accounts, hi->handle, NULL);

    if (!ta) {
        ss_reply("SSMSG_NOT_TRUSTED", argv[2]);
        return 0;
    }

    if (argc > 1) {
        if (ta->channel->used) {
            for (i=0; i < ta->channel->used; i++) {
                if (!strcmp(ta->channel->list[i], argv[2])) {
                    string_list_delete(ta->channel, i);
                    rem = 1;
                }
            }
        }

        if (rem == 1)
            ss_reply("SSMSG_REMOVED_TRUSTED_CHANNEL", hi->handle, argv[2]);
        else {
            ss_reply("SSMSG_NOT_TRUSTED", argv[2]);
            return 0;
        }
    } else {
        dict_remove(spamserv_trusted_accounts, hi->handle);
        ss_reply("SSMSG_REMOVED_TRUSTED", hi->handle);
    }

    return 1;
}

static SPAMSERV_FUNC(cmd_listtrust) {
    dict_iterator_t it;
    struct trusted_account *ta;
    char issued[INTERVALLEN];
    char *chan;
    unsigned int i;

    if (argc > 0) {
        if (!strcmp(argv[1], "global")) {
            if (!IsHelping(user)) {
                reply("SSMSG_MUST_BE_HELPING");
                return 0;
            } else
                chan = "global";
        } else {
            channel = GetChannel(argv[1]);
            if (channel)
                chan = strdup(channel->name);
            else {
                ss_reply("SSMSG_NOT_REGISTERED", argv[1]);
                return 0;
            }
        }
    } else {
        reply("MSG_INVALID_CHANNEL");
        return 0;
    }

    reply("SSMSG_TRUSTED_LIST");
    reply("SSMSG_TRUSTED_LIST_BAR");
    reply("SSMSG_TRUSTED_LIST_HEADER");
    reply("SSMSG_TRUSTED_LIST_BAR");
    for (it = dict_first(spamserv_trusted_accounts); it; it = iter_next(it)) {
        ta = iter_data(it);

        if (ta->channel->used) {
            for (i=0; i < ta->channel->used; i++) {

                if (!strcmp(ta->channel->list[i], chan)) {
                    if (ta->issued)
                        intervalString(issued, now - ta->issued, user->handle_info);

                    ss_reply("SSMSG_HOST_IS_TRUSTED", iter_key(it),
                            (ta->issuer ? ta->issuer : "<unknown>"),
                            (ta->issued ? issued : "some time"));

                } else if (!strcmp(ta->channel->list[i], "global") && (!strcmp(chan, "global"))) {
                    if (ta->issued)
                        intervalString(issued, now - ta->issued, user->handle_info);

                    ss_reply("SSMSG_HOST_IS_TRUSTED", iter_key(it),
                            (ta->issuer ? ta->issuer : "<unknown>"),
                             (ta->issued ? issued : 0));
                }
            }
        }
    }
    ss_reply("SSMSG_TRUSTED_LIST_END");
    return 1;
}

static void 
to_lower(char *message)
{
	unsigned int i, diff = 'a' - 'A';

	for(i = 0; i < strlen(message); i++)
	{
		if((message[i] >= 'A') && (message[i] <= 'Z'))
			message[i] = message[i] + diff;
	}
}

static char *
strip_mirc_codes(char *text)
{
	// taken from xchat and modified
	int nc = 0, i = 0, col = 0, len = strlen(text);
	static char new_str[MAXLEN];

	while(len > 0)
	{
		if((col && isdigit(*text) && nc < 2) ||
			(col && *text == ',' && isdigit(*(text + 1)) && nc < 3))
		{
			nc++;

			if(*text == ',')
				nc = 0;
		}
		else
		{
			col = 0;

			switch(*text)
			{
			case '\003':
				col = 1;
				nc = 0;
				break;
			case '\002':
			case '\022':
			case '\026':			
			case '\031':
			case '\037':
				break;
			default:
				new_str[i] = *text;
				i++;
			}
		}

		text++;
		len--;
	}

	new_str[i] = '\0';

	return new_str;
}

static int
is_in_exception_list(struct chanInfo *cInfo, char *message)
{
	unsigned int i;

	for(i = 0; i < cInfo->exceptions->used; i++)
		if(strstr(message, cInfo->exceptions->list[i]))
			return 1;

	return 0;
}

static int
is_in_badword_list(struct chanInfo *cInfo, char *message)
{
	unsigned int i;

	for(i = 0; i < cInfo->badwords->used; i++)
		if(strstr(message, cInfo->badwords->list[i]))
			return 1;

	return 0;
}

static int
check_badwords(struct chanInfo *cInfo, char *message)
{
	if(spamserv_conf.strip_mirc_codes)
		message = strip_mirc_codes(message);

	/* This needs improving */
	if(is_in_exception_list(cInfo, message))
		return 0;

	if(is_in_badword_list(cInfo, message))
		return 1;

	return 0;
}

static int
check_advertising(struct chanInfo *cInfo, char *message)
{
	unsigned int i = 0;

	if(spamserv_conf.strip_mirc_codes)
		message = strip_mirc_codes(message);

	if(is_in_exception_list(cInfo, message))
		return 0;

	while(message[i] != 0)
	{
		if(message[i] == '#')
		{
			char channelname[CHANNELLEN];
			unsigned int j = 0;

			if(!spamserv_conf.adv_chan_must_exist)
				return 1;

			/* only return 1, if the channel does exist */	

			while((message[i] != 0) && (message[i] != ' '))
			{
				channelname[j] = message[i];
				i++;
				j++;				
			}

			channelname[j] = '\0';

			if(GetChannel(channelname))
				return 1;
		}
		else if((message[i] == 'w') && (message[i+1] == 'w') && (message[i+2] == 'w') && (message[i+3] == '.'))
			return 1;
		else if((message[i] == 'h') && (message[i+1] == 't') && (message[i+2] == 't') && (message[i+3] == 'p') && (message[i+4] == ':'))
			return 1;
		else if((message[i] == 'f') && (message[i+1] == 't') && (message[i+2] == 'p') && ((message[i+3] == '.') || (message[i+3] == ':')))
			return 1;

		i++;
	}

	return 0;
}

static void
spamserv_punish(struct chanNode *channel, struct userNode *user, time_t expires, char *reason, int ban)
{
	if(ban)
	{
		struct mod_chanmode change;
		char *hostmask = generate_hostmask(user, GENMASK_STRICT_HOST | GENMASK_ANY_IDENT);

		sanitize_ircmask(hostmask);

		if(expires)
			add_channel_ban(channel->channel_info, hostmask, spamserv->nick, now, now, now + expires, reason);

		mod_chanmode_init(&change);
		change.argc = 1;
		change.args[0].mode = MODE_BAN;
                change.args[0].u.hostmask = hostmask;
		mod_chanmode_announce(spamserv, channel, &change);        

		free(hostmask);

		spamserv_debug(SSMSG_DEBUG_BAN, user->nick, channel->name, reason);
	}
	else
		spamserv_debug(SSMSG_DEBUG_KICK, user->nick, channel->name, reason);

	KickChannelUser(user, channel, spamserv, reason);	
}

void
spamserv_channel_message(struct chanNode *channel, struct userNode *user, char *text)
{
	struct chanData *cData;
	struct chanInfo *cInfo;
	struct userInfo	*uInfo;
	struct userData *uData;
	struct spamNode *sNode;
	struct floodNode *fNode;
        struct trusted_account *ta;
	unsigned int violation = 0;
	char reason[MAXLEN];

	/* make sure: spamserv is not disabled; x3 is running; spamserv is in the chan; chan is regged, user does exist */
	if(!spamserv || quit_services || !GetUserMode(channel, spamserv) || IsOper(user) || !(cInfo = get_chanInfo(channel->name)) || !(uInfo = get_userInfo(user->nick)))
		return;

	cData = channel->channel_info;
	uData = GetChannelUser(cData, user->handle_info);

        if (user->handle_info) {
          ta = dict_find(spamserv_trusted_accounts, user->handle_info->handle, NULL);
          if (ta) {
             unsigned int i = 0;
             for (i=0; i < ta->channel->used; i++) {
                if (!strcmp(ta->channel->list[i], channel->name))
                    return;

                if (!strcmp(ta->channel->list[i], "global"))
                    return;
              }
           }
        }


	if(!CHECK_CHANOPS(cInfo))
	{
		struct modeNode *mn = GetUserMode(channel, user);
		if (mn && (mn->modes & MODE_CHANOP))
			return;
	}

	if(!CHECK_HALFOPS(cInfo))
	{
		struct modeNode *mn = GetUserMode(channel, user);
		if (mn && (mn->modes & MODE_HALFOP))
			return;
	}
	
	if(!CHECK_VOICED(cInfo))
	{
		struct modeNode *mn = GetUserMode(channel, user);
		if (mn && ((mn->modes & MODE_VOICE) && !(mn->modes & MODE_CHANOP) && !(mn->modes & MODE_HALFOP)))
			return;
	}

        if(uData && (uData->access >= cInfo->exceptlevel))
            return;

	to_lower(text);

	if(CHECK_SPAM(cInfo))
	{
		if(!(sNode = uInfo->spam))
		{
			spamserv_create_spamNode(channel, uInfo, text);
		}
		else
		{
			for(; sNode; sNode = sNode->next)
				if(sNode->channel == channel)
					break;

			if(!sNode)
			{
				spamserv_create_spamNode(channel, uInfo, text);
			}
			else
			{
				unsigned long crc = crc32(text);

				if(crc == sNode->crc32)
				{
					unsigned int spamlimit = 2;
					sNode->count++;

					switch(cInfo->info[ci_SpamLimit])
					{
						case 'a': spamlimit = 2; break;
						case 'b': spamlimit = 3; break;
						case 'c': spamlimit = 4; break;
						case 'd': spamlimit = 5; break;
						case 'e': spamlimit = 6; break;
					}

					if(sNode->count == spamlimit)
					{
						uInfo->warnlevel += SPAM_WARNLEVEL;

						if(uInfo->warnlevel < MAX_WARNLEVEL) {
							if (spamserv_conf.network_rules)
								spamserv_notice(user, "SSMSG_WARNING_RULES_T", SSMSG_SPAM, spamserv_conf.network_rules);
							else
								spamserv_notice(user, "SSMSG_WARNING_T", SSMSG_SPAM, spamserv_conf.network_rules);
						}
					}
					else if(sNode->count > spamlimit)
					{
						switch(cInfo->info[ci_WarnReaction])
						{
							case 'k': uInfo->flags |= USER_KICK; break;
							case 'b': uInfo->flags |= USER_KICKBAN; break;
							case 's': uInfo->flags |= USER_SHORT_TBAN; break;
							case 'l': uInfo->flags |= USER_LONG_TBAN; break;
							case 'd': uInfo->flags |= CHECK_KILLED(uInfo) ? USER_GLINE : USER_KILL; break;
						}

						spamserv_delete_spamNode(uInfo, sNode);
						uInfo->warnlevel += SPAM_WARNLEVEL;
						violation = 1;
					}
				}
				else
				{
					sNode->crc32 = crc;					
					sNode->count = 1;
				}
			}
		}
	}

	if(CHECK_FLOOD(cInfo))
	{
		if(!(fNode = uInfo->flood))
		{
			spamserv_create_floodNode(channel, user, &uInfo->flood);
		}
		else
		{
			for(; fNode; fNode = fNode->next)
				if(fNode->channel == channel)
					break;
				
			if(!fNode) {
				spamserv_create_floodNode(channel, user, &uInfo->flood);
			} else {
				if(((now - fNode->time) < FLOOD_EXPIRE)) {
					fNode->count++;
					
					if(fNode->count == FLOOD_MAX_LINES - 1) {
					    uInfo->warnlevel += FLOOD_WARNLEVEL;

					    if(uInfo->warnlevel < MAX_WARNLEVEL) {
						if (spamserv_conf.network_rules)
						    spamserv_notice(user, "SSMSG_WARNING_RULES_T", SSMSG_FLOOD, spamserv_conf.network_rules);
						else
						    spamserv_notice(user, "SSMSG_WARNING_T", SSMSG_FLOOD, spamserv_conf.network_rules);
					    }
				            fNode->time = now;
					}
					else if(fNode->count > FLOOD_MAX_LINES) {
						switch(cInfo->info[ci_WarnReaction]) {
							case 'k': uInfo->flags |= USER_KICK; break;
							case 'b': uInfo->flags |= USER_KICKBAN; break;
							case 's': uInfo->flags |= USER_SHORT_TBAN; break;
							case 'l': uInfo->flags |= USER_LONG_TBAN; break;
							case 'd': uInfo->flags |= CHECK_KILLED(uInfo) ? USER_GLINE : USER_KILL; break;
						}

						spamserv_delete_floodNode(&uInfo->flood, fNode);
						uInfo->warnlevel += FLOOD_WARNLEVEL;
						violation = 2;						
					}
				} else {
				    fNode->time = now;
                                }
			}
		}
	}

	if(CHECK_BADWORDSCAN(cInfo) && check_badwords(cInfo, text))
	{
		if(CHECK_BAD_WARNED(uInfo))
		{
			switch(cInfo->info[ci_BadReaction])
			{
				case 'k': uInfo->flags |= USER_KICK; break;
				case 'b': uInfo->flags |= USER_KICKBAN; break;
				case 's': uInfo->flags |= USER_SHORT_TBAN; break;
				case 'l': uInfo->flags |= USER_LONG_TBAN; break;
				case 'd': uInfo->flags |= CHECK_KILLED(uInfo) ? USER_GLINE : USER_KILL; break;
			}

			uInfo->warnlevel += BAD_WARNLEVEL;
			violation = 4;
		}
		else
		{		
			uInfo->flags |= USER_BAD_WARNED;
			uInfo->lastbad = now;
			uInfo->warnlevel += BAD_WARNLEVEL;

			if(uInfo->warnlevel < MAX_WARNLEVEL) {
				if (spamserv_conf.network_rules)
					spamserv_notice(user, "SSMSG_WARNING_RULES_T", SSMSG_BAD, spamserv_conf.network_rules);
				else
					spamserv_notice(user, "SSMSG_WARNING_T", SSMSG_BAD, spamserv_conf.network_rules);
			}
		}
	}

	if(CHECK_ADV(cInfo) && check_advertising(cInfo, text))
	{
		if(CHECK_ADV_WARNED(uInfo))
		{
			switch(cInfo->info[ci_AdvReaction])
			{
				case 'k': uInfo->flags |= USER_KICK; break;
				case 'b': uInfo->flags |= USER_KICKBAN; break;
				case 's': uInfo->flags |= USER_SHORT_TBAN; break;
				case 'l': uInfo->flags |= USER_LONG_TBAN; break;
				case 'd': uInfo->flags |= CHECK_KILLED(uInfo) ? USER_GLINE : USER_KILL; break;
			}

			uInfo->warnlevel += ADV_WARNLEVEL;
			violation = 3;
		}
		else
		{		
			uInfo->flags |= USER_ADV_WARNED;
			uInfo->lastadv = now;
			uInfo->warnlevel += ADV_WARNLEVEL;

			if(uInfo->warnlevel < MAX_WARNLEVEL) {
				if (spamserv_conf.network_rules)
					spamserv_notice(user, "SSMSG_WARNING_RULES_T", SSMSG_ADV, spamserv_conf.network_rules);
				else
					spamserv_notice(user, "SSMSG_WARNING_T", SSMSG_ADV, spamserv_conf.network_rules);
			}
		}
	}

	if(!CHECK_WARNED(uInfo) && !CHECK_KILL(uInfo) && !CHECK_GLINE(uInfo) && uInfo->warnlevel == MAX_WARNLEVEL)
	{
		uInfo->flags |= USER_WARNED;
                if (spamserv_conf.network_rules)
			snprintf(reason, sizeof(reason), SSMSG_WARNING_RULES_2, spamserv_conf.network_rules);
		else
			snprintf(reason, sizeof(reason), SSMSG_WARNING_2);
		irc_notice(spamserv, user->numeric, reason);
		irc_privmsg(spamserv, user->numeric, reason);
	}
	else if(uInfo->warnlevel > MAX_WARNLEVEL)
	{
		if(CHECK_KILLED(uInfo))
			uInfo->flags |= USER_GLINE;
		else
			uInfo->flags |= USER_KILL;

		violation = 5;
	}

	if(!violation)
		return;

	switch(violation)
	{

		case 1: snprintf(reason, sizeof(reason), spamserv_conf.network_rules ? SSMSG_WARNING_RULES : SSMSG_WARNING, SSMSG_SPAM, spamserv_conf.network_rules); break;
		case 2: snprintf(reason, sizeof(reason), spamserv_conf.network_rules ? SSMSG_WARNING_RULES : SSMSG_WARNING, SSMSG_FLOOD, spamserv_conf.network_rules); break;
		case 3: snprintf(reason, sizeof(reason), spamserv_conf.network_rules ? SSMSG_WARNING_RULES : SSMSG_WARNING, SSMSG_ADV, spamserv_conf.network_rules); break;
		case 4: snprintf(reason, sizeof(reason), spamserv_conf.network_rules ? SSMSG_WARNING_RULES : SSMSG_WARNING, SSMSG_BAD, spamserv_conf.network_rules); break;
		default: snprintf(reason, sizeof(reason), spamserv_conf.network_rules ? SSMSG_WARNING_RULES_2 : SSMSG_WARNING_2, spamserv_conf.network_rules); break;
	}

	if(CHECK_GLINE(uInfo))
	{
		int size = strlen(user->hostname) + 3;
		char *mask = alloca(size);
		snprintf(mask, size, "*@%s", user->hostname);
		gline_add(spamserv->nick, mask, spamserv_conf.gline_duration, reason, now, 1, 0);
		spamserv_debug(SSMSG_DEBUG_GLINE, user->nick, user->hostname, channel->name);
	}
	else if(CHECK_KILL(uInfo))
	{
		DelUser(user, spamserv, 1, reason);
		spamserv_debug(SSMSG_DEBUG_KILL, user->nick, channel->name);
	}
	else if(CHECK_LONG_TBAN(uInfo))
	{
		spamserv_punish(channel, user, spamserv_conf.long_ban_duration, reason, 1);
	}
	else if(CHECK_SHORT_TBAN(uInfo))
	{
		spamserv_punish(channel, user, spamserv_conf.short_ban_duration, reason, 1);
	}
	else if(CHECK_KICKBAN(uInfo))
	{
		spamserv_punish(channel, user, 0, reason, 1);
	}
	else if(CHECK_KICK(uInfo))
	{
		spamserv_punish(channel, user, 0, reason, 0);
	}
}

static int
trusted_account_read(const char *account, void *data, UNUSED_ARG(void *extra))
{
    struct record_data *rd = data;
    const char *str, *issuer;
    struct string_list *strlist;
    time_t issued;

    if (rd->type == RECDB_OBJECT) {
        dict_t obj = GET_RECORD_OBJECT(rd);
        /* new style structure */
        strlist = database_get_data(obj, KEY_CHANNELS, RECDB_STRING_LIST);
        issuer = database_get_data(obj, KEY_ISSUER, RECDB_QSTRING);
        str = database_get_data(obj, KEY_ISSUED, RECDB_QSTRING);
        issued = str ? ParseInterval(str) : 0;
    } else
        return 0;

    spamserv_add_trusted_account(account, strlist, issuer, issued);
    return 0;
}

static int
spamserv_saxdb_read(struct dict *database)
{
	dict_iterator_t it;
	struct record_data *hir;
	struct chanNode	*channel;
	struct chanInfo	*cInfo;
	struct string_list *strlist, *strlist2;
	unsigned int flags, exceptlevel;
	char *str, *info;	
	time_t expiry;    
	dict_t object;

	if ((object = database_get_data(database, KEY_TRUSTED_HOSTS, RECDB_OBJECT)))
		dict_foreach(object, trusted_account_read, spamserv_trusted_accounts);

	for(it = dict_first(database); it; it = iter_next(it))
	{
		hir = iter_data(it);

		if(hir->type != RECDB_OBJECT)
		{
			log_module(SS_LOG, LOG_WARNING, "Unexpected rectype %d for %s.", hir->type, iter_key(it));
			continue;
		}

		channel = GetChannel(iter_key(it));
                if (!strcmp("trusted", iter_key(it)))
                    continue;

		strlist = database_get_data(hir->d.object, KEY_EXCEPTIONS, RECDB_STRING_LIST);
		strlist2 = database_get_data(hir->d.object, KEY_BADWORDS, RECDB_STRING_LIST);

		str = database_get_data(hir->d.object, KEY_FLAGS, RECDB_QSTRING);
		flags = str ? atoi(str) : 0;

		info = database_get_data(hir->d.object, KEY_INFO, RECDB_QSTRING);

		str = database_get_data(hir->d.object, KEY_EXPIRY, RECDB_QSTRING);
		expiry = str ? strtoul(str, NULL, 0) : 0;

		str = database_get_data(hir->d.object, KEY_EXCEPTLEVEL, RECDB_QSTRING);
		exceptlevel = str ? strtoul(str, NULL, 0) : UL_MANAGER;

		if(channel && info)
		{
			if((cInfo = spamserv_register_channel(channel, strlist, strlist2, flags, info)))
			{
				/* if the channel is suspended and expiry = 0 it means: channel will
				   never expire ! it does NOT mean, the channel is not suspended */
				if(CHECK_SUSPENDED(cInfo) && expiry && (expiry < now))
				{
					cInfo->flags &= ~CHAN_SUSPENDED;
					spamserv_join_channel(cInfo->channel);
				}
				else if(!CHECK_SUSPENDED(cInfo))
					spamserv_join_channel(cInfo->channel);
				else
					cInfo->suspend_expiry = expiry;

				cInfo->exceptlevel = exceptlevel;
			}
		}
		else
			log_module(SS_LOG, LOG_ERROR, "Couldn't register channel %s. Channel or info invalid.", iter_key(it));	
	}

	return 0;
}

static int
spamserv_saxdb_write(struct saxdb_context *ctx)
{
	dict_iterator_t it;

        if (dict_size(spamserv_trusted_accounts)) {
            saxdb_start_record(ctx, KEY_TRUSTED_ACCOUNTS, 1);
            for (it = dict_first(spamserv_trusted_accounts); it; it = iter_next(it)) {
                struct trusted_account *ta = iter_data(it);
                saxdb_start_record(ctx, iter_key(it), 0);
                if (ta->channel) saxdb_write_string_list(ctx, KEY_CHANNELS, ta->channel);
                if (ta->issued) saxdb_write_int(ctx, KEY_ISSUED, ta->issued);
                if (ta->issuer) saxdb_write_string(ctx, KEY_ISSUER, ta->issuer);
                saxdb_end_record(ctx);
            }
            saxdb_end_record(ctx);
        }

	for(it = dict_first(registered_channels_dict); it; it = iter_next(it))
	{
		struct chanInfo *cInfo = iter_data(it);

		saxdb_start_record(ctx, cInfo->channel->name, 1);

		if(cInfo->exceptions->used)
			saxdb_write_string_list(ctx, KEY_EXCEPTIONS, cInfo->exceptions);

		if(cInfo->badwords->used)
			saxdb_write_string_list(ctx, KEY_BADWORDS, cInfo->badwords);

		if(cInfo->flags)
			saxdb_write_int(ctx, KEY_FLAGS, cInfo->flags);

		if(cInfo->exceptlevel)
			saxdb_write_int(ctx, KEY_EXCEPTLEVEL, cInfo->exceptlevel);

		saxdb_write_string(ctx, KEY_INFO, cInfo->info);			

		if(cInfo->suspend_expiry)
			saxdb_write_int(ctx, KEY_EXPIRY, cInfo->suspend_expiry);		

		saxdb_end_record(ctx);		
	}
	return 0;
}

static void
spamserv_conf_read(void)
{
	dict_t conf_node;
	const char *str; 

	if(!(conf_node = conf_get_data(SPAMSERV_CONF_NAME, RECDB_OBJECT)))
	{
		log_module(SS_LOG, LOG_ERROR, "config node `%s' is missing or has wrong type.", SPAMSERV_CONF_NAME);
		return;
	}

	str = database_get_data(conf_node, KEY_DEBUG_CHANNEL, RECDB_QSTRING);

	if(str)
	{
		spamserv_conf.debug_channel = AddChannel(str, now, "+tinms", NULL, NULL);

		if(spamserv_conf.debug_channel)
			spamserv_join_channel(spamserv_conf.debug_channel);
	}
	else
	{
		spamserv_conf.debug_channel = NULL;
	}

	spamserv_conf.global_exceptions = database_get_data(conf_node, KEY_GLOBAL_EXCEPTIONS, RECDB_STRING_LIST);

	spamserv_conf.global_badwords = database_get_data(conf_node, KEY_GLOBAL_BADWORDS, RECDB_STRING_LIST);

	str = database_get_data(conf_node, KEY_NETWORK_RULES, RECDB_QSTRING);
	spamserv_conf.network_rules = str ? str : NULL;

	str = database_get_data(conf_node, KEY_TRIGGER, RECDB_QSTRING);
	spamserv_conf.trigger = str ? str[0] : 0;

	str = database_get_data(conf_node, KEY_SHORT_BAN_DURATION, RECDB_QSTRING);
	spamserv_conf.short_ban_duration = str ? ParseInterval(str) : ParseInterval("15m");

	str = database_get_data(conf_node, KEY_LONG_BAN_DURATION, RECDB_QSTRING);
	spamserv_conf.long_ban_duration = str ? ParseInterval(str) : ParseInterval("1h");

	str = database_get_data(conf_node, KEY_GLINE_DURATION, RECDB_QSTRING);
	spamserv_conf.gline_duration = str ? ParseInterval(str) : ParseInterval("1h");

	str = database_get_data(conf_node, KEY_EXCEPTION_MAX, RECDB_QSTRING);
	spamserv_conf.exception_max = str ? strtoul(str, NULL, 0) : 10;

	str = database_get_data(conf_node, KEY_EXCEPTION_MIN_LEN, RECDB_QSTRING);
	spamserv_conf.exception_min_len = str ? strtoul(str, NULL, 0) : 4;

	str = database_get_data(conf_node, KEY_EXCEPTION_MAX_LEN, RECDB_QSTRING);
	spamserv_conf.exception_max_len = str ? strtoul(str, NULL, 0) : 15;

	str = database_get_data(conf_node, KEY_BADWORD_MAX, RECDB_QSTRING);
	spamserv_conf.badword_max = str ? strtoul(str, NULL, 0) : 10;

	str = database_get_data(conf_node, KEY_BADWORD_MIN_LEN, RECDB_QSTRING);
	spamserv_conf.badword_min_len = str ? strtoul(str, NULL, 0) : 4;

	str = database_get_data(conf_node, KEY_BADWORD_MAX_LEN, RECDB_QSTRING);
	spamserv_conf.badword_max_len = str ? strtoul(str, NULL, 0) : 15;

	str = database_get_data(conf_node, KEY_ADV_CHAN_MUST_EXIST, RECDB_QSTRING);
	spamserv_conf.adv_chan_must_exist = str ? enabled_string(str) : 1;

	str = database_get_data(conf_node, KEY_STRIP_MIRC_CODES, RECDB_QSTRING);
	spamserv_conf.strip_mirc_codes = str ? enabled_string(str) : 0;

	str = database_get_data(conf_node, KEY_ALLOW_MOVE_MERGE, RECDB_QSTRING);
	spamserv_conf.allow_move_merge = str ? enabled_string(str) : 0;
}

static void
spamserv_db_cleanup(void)
{
	dict_iterator_t it;

	while((it = dict_first(registered_channels_dict)))
	{
		spamserv_unregister_channel(iter_data(it));
	}

/* now handled automatically
 *	while((it = dict_first(killed_users_dict)))
	{
		free(iter_data(it));
	}
*/
	
	dict_delete(registered_channels_dict);
	dict_delete(connected_users_dict);
	dict_delete(killed_users_dict);
	dict_delete(spamserv_trusted_accounts);
}

void
init_spamserv(const char *nick)
{
        struct chanNode *chan;
        unsigned int i;

	if(!nick)
		return;

        const char *modes = conf_get_data("services/spamserv/modes", RECDB_QSTRING);
	spamserv = AddService(nick, modes ? modes : NULL, "Anti Spam Services", NULL);
	spamserv_service = service_register(spamserv);

	conf_register_reload(spamserv_conf_read);

	SS_LOG = log_register_type("SpamServ", "file:spamserv.log");	

        /* auto-free the keys for these dicts,
         * and auto-free the keys AND data for killed_users_dict.
         * other data need free'd manually. */
	registered_channels_dict = dict_new();
        dict_set_free_keys(registered_channels_dict, free);
	connected_users_dict = dict_new();
        dict_set_free_keys(connected_users_dict, free);
	killed_users_dict = dict_new();
        dict_set_free_keys(killed_users_dict, free);
        dict_set_free_data(killed_users_dict, free);
        spamserv_trusted_accounts = dict_new();
        dict_set_free_keys(spamserv_trusted_accounts, free);
        dict_set_free_data(spamserv_trusted_accounts, free);

	saxdb_register("SpamServ", spamserv_saxdb_read, spamserv_saxdb_write);

	reg_new_user_func(spamserv_new_user_func);
	reg_del_user_func(spamserv_del_user_func);
	reg_nick_change_func(spamserv_nick_change_func);
	reg_join_func(spamserv_user_join);
	reg_part_func(spamserv_user_part);

	timeq_add(now + FLOOD_TIMEQ_FREQ, timeq_flood, NULL);
	timeq_add(now + JOINFLOOD_TIMEQ_FREQ, timeq_joinflood, NULL);
	timeq_add(now + ADV_TIMEQ_FREQ, timeq_adv, NULL);
	timeq_add(now + BAD_TIMEQ_FREQ, timeq_bad, NULL);
	timeq_add(now + WARNLEVEL_TIMEQ_FREQ, timeq_warnlevel, NULL);
	timeq_add(now + KILL_TIMEQ_FREQ, timeq_kill, NULL);

	spamserv_module = module_register("SpamServ", SS_LOG, "spamserv.help", NULL);

	modcmd_register(spamserv_module, "ADDTRUST", cmd_addtrust, 3, MODCMD_REQUIRE_AUTHED, "flags", "+acceptchan", NULL);
	modcmd_register(spamserv_module, "DELTRUST", cmd_deltrust, 3, MODCMD_REQUIRE_AUTHED, "flags", "+acceptchan", NULL);
	modcmd_register(spamserv_module, "OADDTRUST", cmd_oaddtrust, 3, MODCMD_REQUIRE_AUTHED, "flags", "+acceptchan,+helping", NULL);
	modcmd_register(spamserv_module, "ODELTRUST", cmd_odeltrust, 3, MODCMD_REQUIRE_AUTHED, "flags", "+acceptchan,+helping", NULL);
	modcmd_register(spamserv_module, "LISTTRUST", cmd_listtrust, 2, MODCMD_REQUIRE_AUTHED, NULL);
	modcmd_register(spamserv_module, "REGISTER", cmd_register, 1, MODCMD_REQUIRE_AUTHED|MODCMD_REQUIRE_CHANNEL, "flags", "+acceptchan,+helping", NULL);
	modcmd_register(spamserv_module, "UNREGISTER", cmd_unregister, 1, MODCMD_REQUIRE_AUTHED|MODCMD_REQUIRE_CHANNEL, "flags", "+loghostmask", NULL);
	modcmd_register(spamserv_module, "ADDEXCEPTION", cmd_addexception, 1, MODCMD_REQUIRE_AUTHED|MODCMD_REQUIRE_CHANNEL, NULL);
	modcmd_register(spamserv_module, "DELEXCEPTION", cmd_delexception, 1, MODCMD_REQUIRE_AUTHED|MODCMD_REQUIRE_CHANNEL, NULL);
	modcmd_register(spamserv_module, "ADDBADWORD", cmd_addbadword, 1, MODCMD_REQUIRE_AUTHED|MODCMD_REQUIRE_CHANNEL, NULL);
	modcmd_register(spamserv_module, "DELBADWORD", cmd_delbadword, 1, MODCMD_REQUIRE_AUTHED|MODCMD_REQUIRE_CHANNEL, NULL);
	modcmd_register(spamserv_module, "STATUS", cmd_status, 1, 0, NULL);
	modcmd_register(spamserv_module, "SET", cmd_set, 1, MODCMD_REQUIRE_AUTHED|MODCMD_REQUIRE_CHANNEL, NULL);
	modcmd_register(spamserv_module, "SET EXCEPTLEVEL", opt_exceptlevel, 1, MODCMD_REQUIRE_AUTHED|MODCMD_REQUIRE_CHANNEL, NULL);
	modcmd_register(spamserv_module, "SET SPAMLIMIT", opt_spamlimit, 1, MODCMD_REQUIRE_AUTHED|MODCMD_REQUIRE_CHANNEL, NULL);
	modcmd_register(spamserv_module, "SET BADREACTION", opt_badreaction, 1, MODCMD_REQUIRE_AUTHED|MODCMD_REQUIRE_CHANNEL, NULL);
	modcmd_register(spamserv_module, "SET ADVREACTION", opt_advreaction, 1, MODCMD_REQUIRE_AUTHED|MODCMD_REQUIRE_CHANNEL, NULL);
	modcmd_register(spamserv_module, "SET WARNREACTION", opt_warnreaction, 1, MODCMD_REQUIRE_AUTHED|MODCMD_REQUIRE_CHANNEL, NULL);
	modcmd_register(spamserv_module, "SET ADVSCAN", opt_advscan, 1, MODCMD_REQUIRE_AUTHED|MODCMD_REQUIRE_CHANNEL, NULL);
	modcmd_register(spamserv_module, "SET BADWORDSCAN", opt_badwordscan, 1, MODCMD_REQUIRE_AUTHED|MODCMD_REQUIRE_CHANNEL, NULL);
	modcmd_register(spamserv_module, "SET SPAMSCAN", opt_spamscan, 1, MODCMD_REQUIRE_AUTHED|MODCMD_REQUIRE_CHANNEL, NULL);
	modcmd_register(spamserv_module, "SET CHANFLOODSCAN", opt_chanfloodscan, 1, MODCMD_REQUIRE_AUTHED|MODCMD_REQUIRE_CHANNEL, NULL);
	modcmd_register(spamserv_module, "SET JOINFLOODSCAN", opt_joinflood, 1, MODCMD_REQUIRE_AUTHED|MODCMD_REQUIRE_CHANNEL, NULL);
	modcmd_register(spamserv_module, "SET SCANCHANOPS", opt_scanops, 1, MODCMD_REQUIRE_AUTHED|MODCMD_REQUIRE_CHANNEL, NULL);
	modcmd_register(spamserv_module, "SET SCANHALFOPS", opt_scanhalfops, 1, MODCMD_REQUIRE_AUTHED|MODCMD_REQUIRE_CHANNEL, NULL);
	modcmd_register(spamserv_module, "SET SCANVOICED", opt_scanvoiced, 1, MODCMD_REQUIRE_AUTHED|MODCMD_REQUIRE_CHANNEL, NULL);

	spamserv_service->trigger = spamserv_conf.trigger;


        if (autojoin_channels && spamserv) {
            for (i = 0; i < autojoin_channels->used; i++) {
                chan = AddChannel(autojoin_channels->list[i], now, "+nt", NULL, NULL);
                AddChannelUser(spamserv, chan)->modes |= MODE_CHANOP;
            }
        }

	reg_exit_func(spamserv_db_cleanup);
	message_register_table(msgtab);
	crc32_init();
}
