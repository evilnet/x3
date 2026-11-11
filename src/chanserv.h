/* chanserv.h - Channel service bot
 * Copyright 2000-2004 srvx Development Team
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

#ifndef _chanserv_h
#define _chanserv_h

#include "nickserv.h"

enum UL_ALIASES {
    UL_PEON = 1,
    UL_HALFOP = 150,
    UL_OP = 200,
    UL_MANAGER = 300,
    UL_PRESENT = UL_MANAGER, /* Level needed to keep the channel active */
    UL_COOWNER = 400,
    UL_OWNER = 500,
    UL_HELPER = 600,
};

enum levelOption {
    lvlEnfOps,
    lvlEnfHalfOps,
    lvlEnfModes,
    lvlEnfTopic,
    lvlPubCmd,
    lvlSetters,
    lvlUserInfo,
    lvlInviteMe,
    lvlTopicSnarf,
    NUM_LEVEL_OPTIONS
};

enum charOption {
    chAutomode,
    chProtect,
    chToys,
    chTopicRefresh,
    chCTCPReaction,
    chBanTimeout,
    chResync,
    NUM_CHAR_OPTIONS
};

#define CHANNEL_NODELETE	0x00000001 /* (1 << 0) */
#define CHANNEL_SUSPENDED	0x00000002 /* (1 << 1) */
#define CHANNEL_INFO_LINES	0x00000004 /* (1 << 2) - DEPRECATED */
#define CHANNEL_VOICE_ALL    	0x00000008 /* (1 << 3) - DEPRECATED */

/* No longer used. */                      /* (1 << 4) */
#define CHANNEL_DYNAMIC_LIMIT	0x00000020 /* (1 << 5) */
#define CHANNEL_TOPIC_SNARF	0x00000040 /* (1 << 6) - DEPRECATED */
#define CHANNEL_PEON_INVITE     0x00000080 /* (1 << 7) - DEPRECATED */
#define CHANNEL_OFFCHANNEL      0x00000100 /* (1 << 8) */
#define CHANNEL_HOP_ALL         0x00000200 /* (1 << 9) */
#define CHANNEL_UNREVIEWED      0x00000400 /* (1 << 10) */

/* Flags with values over 0x20000000 or (1 << 29) will not work
 * because chanData.flags is a 30-bit field.
 */

/* how many seconds a pending adduser will wait for a user
 * to get auth or register 
 */
#define ADDUSER_PENDING_EXPIRE 7200  /* 2 hours */

#define IsProtected(x)		((x)->flags & CHANNEL_NODELETE)
#define IsSuspended(x)		((x)->flags & CHANNEL_SUSPENDED)
#define IsOffChannel(x)         (((x)->flags & CHANNEL_OFFCHANNEL) && (off_channel > 1))

struct renamed_from;

struct chanData
{
    struct chanNode	*channel;
    struct mod_chanmode modes;

    time_t		registered;
    time_t		visited;
    time_t 		limitAdjusted;
    time_t              ownerTransfer;
    time_t              markersRestored; /* last chanserv_markers_changed() put-back; not saved */

    char		*topic;
    char		*greeting;
    char		*user_greeting;
    char		*registrar;
    char                *topic_mask;

    unsigned int        maxsetinfo;
    unsigned int	flags : 30;
    unsigned int        may_opchan : 1;
    unsigned int        max;
    unsigned int        last_refresh;
    unsigned int        last_resync;
    unsigned int        roulette_chamber;
    unsigned short      banCount; /* Lamers, really */
    unsigned short      userCount;
    unsigned short      lvlOpts[NUM_LEVEL_OPTIONS];
    unsigned char       chOpts[NUM_CHAR_OPTIONS];

    struct userData	*users;
    struct banData	*bans; /* Lamers, really */
    struct dict         *notes;
    struct suspended	*suspended;
    struct giveownership *giveownership;
    struct renamed_from *renamed_from; /* names it was renamed away from, while their rename DNR stands */
    struct chanData	*prev;
    struct chanData	*next;
};

#define USER_NOAUTO_OP          0x00000001 /* OLD; Not used at all.. */
#define USER_SUSPENDED          0x00000002
#define USER_AUTO_INVITE        0x00000004
#define USER_AUTO_OP            0x00000008
#define USER_AUTO_JOIN          0x00000010
#define USER_FLAGS_SIZE         25
#define USER_FLAGS_DEFAULT      USER_AUTO_OP

#define IsUserAutoOp(USER)      ((USER)->flags & USER_AUTO_OP)
#define IsUserSuspended(USER)   ((USER)->flags & USER_SUSPENDED)
#define IsUserAutoInvite(USER)  ((USER)->flags & USER_AUTO_INVITE)
#define IsUserAutoJoin(USER)    ((USER)->flags & USER_AUTO_JOIN)

struct userData
{
    struct handle_info	*handle;
    struct chanData	*channel;

    char		*info;
    time_t 		seen;
    time_t              expires;
    time_t              accessexpiry;
    time_t              clvlexpiry;
    unsigned short      lastaccess;
    unsigned short      access;
    unsigned int	present : 1;
    unsigned int        flags : USER_FLAGS_SIZE;

    /* linked list of userDatas for a chanData */
    struct userData	*prev;
    struct userData	*next;
    /* linked list of userDatas for a handle_info */
    struct userData     *u_prev;
    struct userData     *u_next;
};

struct adduserPending
{
    struct chanNode *channel;
    struct userNode *user;
    int level;
    time_t created;

    struct adduserPending *prev;
    struct adduserPending *next;
};

struct banData
{
    char		mask[NICKLEN + USERLEN + HOSTLEN + 3];
    char		owner[NICKLEN+1];
    struct chanData     *channel;

    time_t		set;
    time_t		triggered;
    time_t              expires;

    char		*reason;

    struct banData	*prev;
    struct banData	*next;
};

struct suspended
{
    struct chanData	*cData;
    char		*suspender;
    char                *reason;
    time_t              issued, expires, revoked;
    struct suspended    *previous;
};

struct giveownership
{
    char                 *staff_issuer;
    char                  *old_owner;
    char                  *target;
    unsigned short        target_access;
    time_t                issued;
    char                  *reason;
    struct giveownership  *previous;
};

struct do_not_register
{
    char   chan_name[CHANNELLEN+1];
    char   setter[NICKSERV_HANDLE_LEN+1];
    time_t set, expires; 
    char   reason[1];
};

#define GetChannelUser(channel, handle) _GetChannelUser(channel, handle, 1, 0)
struct userData *_GetChannelUser(struct chanData *channel, struct handle_info *handle, int override, int allow_suspended);
struct banData *add_channel_ban(struct chanData *channel, const char *mask, char *owner, time_t set, time_t triggered, time_t expires, char *reason);

/* Rename authorization check, used by the AC R RENAME query handler in
 * proto-p10.c (cmd_account). Returns 1 = allow; 0 = deny with *reason
 * set to a static user-visible string. */
int chanserv_rename_allowed(struct userNode *user, struct chanNode *chan, const char *new_name, const char **reason);

/* Called by the RN handler in proto-p10.c (cmd_rename) after a registered
 * channel is renamed (new_chan is the renamed node), to place a timed
 * do-not-register entry on the old name. No-op if
 * chanserv_conf.rename_dnr_duration is 0, or if old_name is already
 * covered by an existing (non-expired) DNR.  If the registration has come
 * back to a name it was renamed away from, the rename DNR it left there is
 * removed first. proto-p10.c must not reach into chanserv's DNR internals
 * (plain_dnrs/mask_dnrs/etc are file-static) — this wrapper is the
 * exported escape hatch. */
void chanserv_rename_dnr(const char *old_name, struct chanNode *new_chan);

/* Called by cmd_rename after it has applied an RN: sends the registered
 * channel's markers (+R, and +z with off_channel on) for its new name once
 * more, whatever X3's copy of the modes says. See the function for the
 * race this repairs. Sends nothing for a channel that is not registered
 * here or whose copy did not carry +R before the rename.
 *
 * chanserv_relocate_markers() is the same for a relocation of a channel
 * that was registered: the markers for the new channel, and -R for the old
 * name, which lives on as the tombstone (NULL when the network has already
 * dissolved it). */
void chanserv_rename_marker(struct chanNode *new_chan);
void chanserv_relocate_markers(struct chanNode *tombstone, struct chanNode *new_chan);

/* Called by cmd_rename after an RN moved a registration, and by
 * relocate_again() when a crossing hands one on: tells opers and helpers,
 * as MOVE does.  source is the RN's origin or a server name, or NULL. */
void chanserv_rename_announce(const char *old_name, struct chanNode *new_chan, const char *source);

/* evilnet/channel-relocate, both called by cmd_rename's consent path in
 * proto-p10.c after the channel has been split.
 *
 * chanserv_relocate_bots() works out again which of the registration's users
 * are present, now that only some of the members are in the new channel, and
 * re-asserts ChanServ's (and SpamServ's) ops on the new node, once the bots
 * have followed the registration there.  The second part is a no-op for an
 * off-channel or suspended registration.
 *
 * chanserv_relocate_tombstone() starts tracking the old node as a tombstone
 * and arms the X3-side reap of it for `expires', the relocation's deadline
 * in network time.  The ircd dissolves its tombstone with local-only PARTs
 * that never reach us, so this is the only thing that stops the husk's
 * member list going stale forever.  new_name is the redirect target, or
 * NULL when it is not known, and target_ts the creation timestamp of the
 * channel under that name.  A deadline that is now or past is acted on
 * before this returns: 0 then, and the members X3 showed in the node are
 * gone (the caller must hold the node if it still needs it); 1 when the
 * tombstone lives on.
 *
 * chanserv_relocate_own_deadline() is the deadline X3 makes up when it is
 * given none: its own relocate_grace from now (with relocate_grace 0, now:
 * dissolved at once). */
void chanserv_relocate_bots(struct chanNode *new_chan);
int chanserv_relocate_tombstone(struct chanNode *channel, const char *new_name, time_t target_ts, time_t expires);
time_t chanserv_relocate_own_deadline(void);

/* The record keeping behind a channel that is relocated twice; proto-p10.c
 * relocate_again() has the rule and moves the members, these keep the
 * records the way the ircd's functions of (nearly) the same names do.
 *
 * chanserv_relocate_husk_get(): is this channel a tombstone X3 tracks that
 * still carries a tombstone's marks (+z, +L)?  Registration is not asked
 * about, as the ircd does not ask.  Returns 1 and the record's target, the
 * target's creation timestamp and the deadline (each pointer may be NULL);
 * the target string is the record's own and changes with it.
 *
 * chanserv_relocate_husk_leftover(): the channel is about to be relocated
 * as an ordinary channel.  A record still kept for it is a tombstone that
 * lost its marks and was waiting out its deadline; it is dropped, and the
 * +z it would have handed back at the deadline is handed back now.
 *
 * chanserv_relocate_retarget(): every tombstone that redirects to
 * old_target redirects to new_target from now on (chain flattening; also
 * how the tombstones that pointed at the loser of a crossing come to
 * point at the winner).
 *
 * chanserv_relocate_loser(): the channel becomes the tombstone of a
 * relocation that lost a crossing -- marked on our copy, with a record
 * redirecting to `winner' -- and belongs to the family of `family', the
 * old channel both relocations were of.  Not settled yet.
 *
 * chanserv_relocate_family_settle(): the old channel's record and every
 * loser's take one deadline and are armed for it; when it is already here
 * they are all dissolved now, and their nodes may be gone on return. */
int chanserv_relocate_husk_get(struct chanNode *channel, const char **target, time_t *target_ts, time_t *expires);
void chanserv_relocate_husk_leftover(struct chanNode *channel);
void chanserv_relocate_retarget(const char *old_target, const char *new_target, time_t target_ts);
void chanserv_relocate_loser(struct chanNode *channel, const char *winner, time_t target_ts, const char *family, time_t expires, int registration_moved);
void chanserv_relocate_family_settle(const char *old_name, time_t deadline);

/* RT: a server announced a tombstone after the channel's BURST.  Builds the
 * record, merges its deadline into one X3 already has, or does nothing
 * when the announcement is not about a channel X3 holds; see the function.
 * `expires' is the deadline as received. */
void chanserv_relocate_announced(const char *old_name, time_t chan_ts, const char *target, time_t expires);

/* For cmd_eob: a channel was burst unregistered with +z and +L and no
 * announcement followed.  Recognises the tombstone of an ircd that does not
 * announce (by the rename DNR on its name) and tracks it by relocate_grace.
 * Returns 1 when it did (the node may be gone when this returns), 0 when
 * the channel is not a tombstone X3 can recognise. */
int chanserv_relocate_husk_fallback(struct chanNode *channel);

/* Is this channel a tombstone X3 is tracking that still looks like one --
 * unregistered, +z, +L?  That is the test the ircd applies before it
 * sweeps one (m_rename.c relocate_tombstone_channel()), on the state X3
 * can see.  Used by cmd_burst's unregistered-channel correction, which
 * must not strip the persist exmode off a live tombstone. */
int chanserv_relocate_husk_live(struct chanNode *channel);

/* For an event that proves the network no longer has the tombstone: a
 * DESTRUCT for it, the name created or joined afresh with a newer
 * timestamp, or another channel renamed onto the name.  If the channel is
 * a tracked tombstone that still looks like one, removes every member X3
 * shows in it -- a local service bot with a PART, the rest silently, as
 * the sweep at the deadline does -- stops tracking it and returns 1; the
 * node is freed unless something else holds it, so the caller must look
 * the name up again.  Otherwise does nothing and returns 0: a channel that
 * lost +z or +L, or was registered, is an ordinary channel again and its
 * members are real. */
int chanserv_relocate_husk_dissolve(struct chanNode *channel, const char *why);

/* Is this channel a tombstone whose deadline has passed and on which X3
 * has not done the deadline's work yet (it waits a few seconds, to be
 * sure not to act before the ircd)?  The network no longer has it as a
 * tombstone; nothing may be built on X3's stale view of it. */
int chanserv_relocate_husk_overdue(struct chanNode *channel);

void init_chanserv(const char *nick);
void del_channel_user(struct userData *user, int do_gc);
struct channelList *chanserv_support_channels(void);
unsigned short user_level_from_name(const char *name, unsigned short clamp_level);
struct do_not_register *chanserv_is_dnr(const char *chan_name, struct handle_info *handle);
int check_user_level(struct chanNode *channel, struct userNode *user, enum levelOption opt, int allow_override, int exempt_owner);

void do_math(char *Buffer, char *Math);
char* user_level_name_from_level(int level);

void process_adduser_pending(struct userNode *user);
void wipe_adduser_pending(struct chanNode *channel, struct userNode *user);

int check_bans(struct userNode *user, const char *channel);
int trace_check_bans(struct userNode *user, struct chanNode *chan);

void chanserv_markers_changed(struct chanNode *channel, const char *source);

#endif
