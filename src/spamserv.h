/* spamserv.h - anti spam service
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
 * along with this program; if not, email srvx-maintainers@srvx.net.
 *
 * $Id$
 */

#ifndef _spamserv_h
#define _spamserv_h

#include "chanserv.h"

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

/***********************************************/
/*                   Channel                   */
/***********************************************/

enum channelinfo
{
    ci_SpamLimit = 0,
    ci_AdvReaction = 4,
    ci_WarnReaction = 3,
    ci_BadReaction = 3,
    ci_CapsReaction = 3,
    ci_Max
};

#define CHAN_INFO_SIZE		(ci_Max + 1)
#define CHAN_INFO_DEFAULT	"blsss"

#define CHAN_SPAMSCAN		0x00000001
#define CHAN_CHANFLOODSCAN	0x00000002
#define CHAN_JOINFLOOD		0x00000004
#define CHAN_ADV_SCAN		0x00000008
#define CHAN_SUSPENDED		0x00000080
#define CHAN_BADWORDSCAN	0x00000100
#define CHAN_CAPSSCAN		0x00000200

#define CHAN_FLAGS_DEFAULT	(CHAN_SPAMSCAN | CHAN_CHANFLOODSCAN | CHAN_JOINFLOOD)

#define CHECK_SPAM(x)		((x)->flags & CHAN_SPAMSCAN)
#define CHECK_FLOOD(x)		((x)->flags & CHAN_CHANFLOODSCAN)
#define CHECK_JOINFLOOD(x)	((x)->flags & CHAN_JOINFLOOD)
#define CHECK_ADV(x)		((x)->flags & CHAN_ADV_SCAN)
#define CHECK_SUSPENDED(x)	((x)->flags & CHAN_SUSPENDED)
#define CHECK_BADWORDSCAN(x)	((x)->flags & CHAN_BADWORDSCAN)
#define CHECK_CAPSSCAN(x)	((x)->flags & CHAN_CAPSSCAN)

struct chanInfo
{
    struct chanNode        *channel;
    struct string_list     *exceptions;
    struct string_list     *badwords;
    unsigned int           exceptlevel;
    unsigned int           exceptadvlevel;
    unsigned int           exceptbadwordlevel;
    unsigned int           exceptcapslevel;
    unsigned int           exceptfloodlevel;
    unsigned int           exceptspamlevel;
    unsigned int           flags : 30;
    int           capsmin;
    int           capspercent;
    char                   info[CHAN_INFO_SIZE+1];
    time_t                 suspend_expiry;
};

/***********************************************/
/*                    User                     */
/***********************************************/

#define USER_KICK           0x00000001
#define USER_KICKBAN        0x00000002
#define USER_SHORT_TBAN     0x00000004
#define USER_LONG_TBAN      0x00000008
#define USER_KILL           0x00000010
#define USER_GLINE          0x00000020
#define USER_WARNED         0x00000040
#define USER_KILLED         0x00000080
#define USER_ADV_WARNED     0x00000100
#define USER_BAD_WARNED     0x00000200
#define USER_CAPS_WARNED    0x00000400

#define CHECK_KICK(x)		((x)->flags & USER_KICK)
#define CHECK_KICKBAN(x)	((x)->flags & USER_KICKBAN)
#define CHECK_SHORT_TBAN(x)	((x)->flags & USER_SHORT_TBAN)
#define CHECK_LONG_TBAN(x)	((x)->flags & USER_LONG_TBAN)
#define CHECK_KILL(x)		((x)->flags & USER_KILL)
#define CHECK_GLINE(x)		((x)->flags & USER_GLINE)
#define CHECK_WARNED(x)		((x)->flags & USER_WARNED)
#define CHECK_KILLED(x)		((x)->flags & USER_KILLED)
#define CHECK_ADV_WARNED(x)	((x)->flags & USER_ADV_WARNED)
#define CHECK_BAD_WARNED(x)	((x)->flags & USER_BAD_WARNED)
#define CHECK_CAPS_WARNED(x)	((x)->flags & USER_CAPS_WARNED)

#define SPAM_WARNLEVEL          1

#define FLOOD_TIMEQ_FREQ        5
#define FLOOD_EXPIRE            5
#define FLOOD_WARNLEVEL         1
#define FLOOD_MAX_LINES         8

#define JOINFLOOD_TIMEQ_FREQ    225
#define JOINFLOOD_EXPIRE        450
#define JOINFLOOD_MAX           3
#define JOINFLOOD_B_DURATION    900

#define ADV_TIMEQ_FREQ          300
#define ADV_EXPIRE              900
#define ADV_WARNLEVEL           2

#define BAD_TIMEQ_FREQ          300
#define BAD_EXPIRE              900
#define BAD_WARNLEVEL           2

#define CAPS_TIMEQ_FREQ          300
#define CAPS_EXPIRE              900
#define CAPS_WARNLEVEL           2

#define WARNLEVEL_TIMEQ_FREQ    1800
#define MAX_WARNLEVEL           6

#define KILL_TIMEQ_FREQ         450
#define KILL_EXPIRE             1800
#define KILL_WARNLEVEL          3

struct spamNode
{
	struct chanNode		*channel;
	unsigned long		crc32;
	unsigned int		count;
	struct spamNode		*prev;
	struct spamNode		*next;
};

struct floodNode
{
	struct chanNode		*channel;
	struct userNode		*owner;
	unsigned int		count;
	time_t        		time;
	struct floodNode	*prev;
	struct floodNode	*next;
};

struct killNode
{
	unsigned int		warnlevel;
	time_t        		time;
};

struct userInfo
{
    struct userNode		*user;
	struct spamNode		*spam;
	struct floodNode	*flood;
	struct floodNode	*joinflood;
	unsigned int		flags : 30;
	unsigned int		warnlevel;
	time_t        		lastadv;
	time_t        		lastbad;
	time_t        		lastcaps;
};

/***********************************************/
/*                 Other Stuff                 */
/***********************************************/

enum cs_unreg
{
    manually,
    expire,
    lost_all_users
};

void init_spamserv(const char *nick);
struct chanInfo *get_chanInfo(const char *channelname);
void spamserv_channel_message(struct chanNode *channel, struct userNode *user, char *text);
void spamserv_cs_suspend(struct chanNode *channel, time_t expiry, int suspend, char *reason);
int  spamserv_cs_move_merge(struct userNode *user, struct chanNode *channel, struct chanNode *target, int move);
void spamserv_cs_unregister(struct userNode *user, struct chanNode *channel, enum cs_unreg type, char *reason);

#endif
