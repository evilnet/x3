/* hash.c - IRC network state database
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

#include "conf.h"
#include "global.h"
#include "hash.h"
#include "log.h"

#if defined(HAVE_LIBGEOIP)&&defined(HAVE_GEOIP_H)&&defined(HAVE_GEOIPCITY_H)
#include <GeoIP.h>
#include <GeoIPCity.h>

GeoIP * gi = NULL;
GeoIP * cgi = NULL;
#endif

struct server *self;
dict_t channels;
dict_t clients;
dict_t servers;
unsigned int max_clients, invis_clients;
time_t max_clients_time;
struct userList curr_opers;

static void hash_cleanup(void);

void init_structs(void)
{
    channels = dict_new();
    clients = dict_new();
    servers = dict_new();
    userList_init(&curr_opers);
    reg_exit_func(hash_cleanup);
}

int userList_contains(struct userList *list, struct userNode *user)
{
    unsigned int ii;

    for (ii = 0; ii < list->used; ++ii) {
        if (user == list->list[ii]) {
            return 1;
        }
    }
    return 0;
}

server_link_func_t *slf_list;
void **slf_list_extra;
unsigned int slf_size = 0, slf_used = 0;

void
reg_server_link_func(server_link_func_t handler, void *extra)
{
    if (slf_used == slf_size) {
        if (slf_size) {
            slf_size <<= 1;
            slf_list = realloc(slf_list, slf_size*sizeof(server_link_func_t));
            slf_list_extra = realloc(slf_list_extra, slf_size*sizeof(void*));
        } else {
            slf_size = 8;
            slf_list = malloc(slf_size*sizeof(server_link_func_t));
            slf_list_extra = malloc(slf_size*sizeof(void*));
        }
    }
    slf_list[slf_used] = handler;
    slf_list_extra[slf_used++] = extra;
}

void
call_server_link_funcs(struct server *server)
{
    unsigned int i;

    for (i = 0; i < slf_used; ++i)
    {
        slf_list[i](server, slf_list_extra[i]);
    }
}

struct server*
GetServerH(const char *name)
{
    return dict_find(servers, name, NULL);
}

new_user_func_t *nuf_list;
void **nuf_list_extra;
unsigned int nuf_size = 0, nuf_used = 0;

void
reg_new_user_func(new_user_func_t handler, void *extra)
{
    if (nuf_used == nuf_size) {
        if (nuf_size) {
            nuf_size <<= 1;
            nuf_list = realloc(nuf_list, nuf_size*sizeof(new_user_func_t));
            nuf_list_extra = realloc(nuf_list_extra, nuf_size*sizeof(void*));
        } else {
            nuf_size = 8;
            nuf_list = malloc(nuf_size*sizeof(new_user_func_t));
            nuf_list_extra = malloc(nuf_size*sizeof(void*));
        }
    }
    nuf_list[nuf_used] = handler;
    nuf_list_extra[nuf_used++] = extra;
}

void
call_new_user_funcs(struct userNode* user)
{
    unsigned int i;

    for (i = 0; i < nuf_used && !(user->dead); ++i)
    {
        nuf_list[i](user, nuf_list_extra[i]);
    }
}

static nick_change_func_t *ncf2_list;
static void **ncf2_list_extra;
static unsigned int ncf2_size = 0, ncf2_used = 0;

void
reg_nick_change_func(nick_change_func_t handler, void *extra)
{
    if (ncf2_used == ncf2_size) {
        if (ncf2_size) {
            ncf2_size <<= 1;
            ncf2_list = realloc(ncf2_list, ncf2_size*sizeof(nick_change_func_t));
            ncf2_list_extra = realloc(ncf2_list_extra, ncf2_size*sizeof(void*));
        } else {
            ncf2_size = 8;
            ncf2_list = malloc(ncf2_size*sizeof(nick_change_func_t));
            ncf2_list_extra = malloc(ncf2_size*sizeof(void*));
        }
    }
    ncf2_list[ncf2_used] = handler;
    ncf2_list_extra[ncf2_used++] = extra;
}


del_user_func_t *duf_list;
void **duf_list_extra;
unsigned int duf_size = 0, duf_used = 0;

void
reg_del_user_func(del_user_func_t handler, void *extra)
{
    if (duf_used == duf_size) {
        if (duf_size) {
            duf_size <<= 1;
            duf_list = realloc(duf_list, duf_size*sizeof(del_user_func_t));
            duf_list_extra = realloc(duf_list_extra, duf_size*sizeof(void*));
        } else {
            duf_size = 8;
            duf_list = malloc(duf_size*sizeof(del_user_func_t));
            duf_list_extra = malloc(duf_size*sizeof(void*));
        }
    }
    duf_list[duf_used] = handler;
    duf_list_extra[duf_used++] = extra;
}

void
call_del_user_funcs(struct userNode *user, struct userNode *killer, const char *why)
{
    unsigned int i;

    for (i = 0; i < duf_used; ++i)
    {
        duf_list[i](user, killer, why, duf_list_extra[i]);
    }
}

void
unreg_del_user_func(del_user_func_t handler, void *extra)
{
    unsigned int i;
    for (i=0; i<duf_used; i++) {
        if (duf_list[i] == handler && duf_list_extra[i] == extra) break;
    }
    if (i == duf_used) return;
    memmove(duf_list+i, duf_list+i+1, (duf_used-i-1)*sizeof(duf_list[0]));
    memmove(duf_list_extra+i, duf_list_extra+i+1, (duf_used-i-1)*sizeof(duf_list_extra[0]));
    duf_used--;
}

/* reintroduces a user after it has been killed. */
void
ReintroduceUser(struct userNode *user)
{
    struct mod_chanmode change;
    unsigned int n;
	
    irc_user(user);
    mod_chanmode_init(&change);
    change.argc = 1;
    for (n = 0; n < user->channels.used; n++) {
        struct modeNode *mn = user->channels.list[n];
	irc_join(user, mn->channel);
        if (mn->modes) {
            change.args[0].mode = mn->modes;
            change.args[0].u.member = mn;
            mod_chanmode_announce(user, mn->channel, &change);
        }
    }
}

void
NickChange(struct userNode* user, const char *new_nick, int no_announce)
{
    char *old_nick;
    unsigned int nn;

    /* don't do anything if there's no change */
    old_nick = user->nick;
    if (!strncmp(new_nick, old_nick, NICKLEN))
        return;

    /* remove old entry from clients dictionary */
    dict_remove(clients, old_nick);
#if !defined(WITH_PROTOCOL_P10)
    /* Remove from uplink's clients dict */
    dict_remove(user->uplink->users, old_nick);
#endif
    /* and reinsert */
    user->nick = strdup(new_nick);
    dict_insert(clients, user->nick, user);
#if !defined(WITH_PROTOCOL_P10)
    dict_insert(user->uplink->users, user->nick, user);
#endif

    /* Make callbacks for nick changes.  Do this with new nick in
     * place because that is slightly more useful.
     */
    for (nn=0; (nn<ncf2_used) && !user->dead; nn++)
        ncf2_list[nn](user, old_nick, ncf2_list_extra[nn]);
    user->timestamp = now;
    if (IsLocal(user) && !no_announce)
        irc_nick(user, old_nick);
    free(old_nick);
}

void
SVSNickChange(struct userNode* user, const char *new_nick)
{
    char *old_nick;
    unsigned int nn;

    /* don't do anything if there's no change */
    old_nick = user->nick;
    if (!strncmp(new_nick, old_nick, NICKLEN))
        return;

    /* remove old entry from clients dictionary */
    dict_remove(clients, old_nick);
#if !defined(WITH_PROTOCOL_P10)
    /* Remove from uplink's clients dict */
    dict_remove(user->uplink->users, old_nick);
#endif
    /* and reinsert */
    user->nick = strdup(new_nick);
    dict_insert(clients, user->nick, user);
#if !defined(WITH_PROTOCOL_P10)
    dict_insert(user->uplink->users, user->nick, user);
#endif

    /* Make callbacks for nick changes.  Do this with new nick in
     * place because that is slightly more useful.
     */
    for (nn=0; (nn<ncf2_used) && !user->dead; nn++)
        ncf2_list[nn](user, old_nick, ncf2_list_extra[nn]);
    user->timestamp = now;

    free(old_nick);
}

struct userNode *
GetUserH(const char *nick)
{
    return dict_find(clients, nick, NULL);
}

static account_func_t account_func;

void
reg_account_func(account_func_t handler)
{
    if (account_func) {
        log_module(MAIN_LOG, LOG_WARNING, "Reregistering ACCOUNT handler.");
    }
    account_func = handler;
}

void
call_account_func(struct userNode *user, const char *stamp)
{
    /* We've received an account stamp for a user; notify
       NickServ, which registers the sole account_func
       right now.  TODO: This is a bug. This needs to register 
       a proper list not just kill with each call!! -Rubin

       P10 Protocol violation if (user->modes & FLAGS_STAMPED) here.
    */
    if (account_func)
        account_func(user, stamp);

#ifdef WITH_PROTOCOL_P10
    /* Mark the user so we don't stamp it again. */
    user->modes |= FLAGS_STAMPED;
#endif
}

void
StampUser(struct userNode *user, const char *stamp, time_t timestamp)
{
#ifdef WITH_PROTOCOL_P10
    /* The P10 protocol says we can't stamp users who already
       have a stamp. */
    if (IsStamped(user))
        return;
#endif

    irc_account(user, stamp, timestamp);
    user->modes |= FLAGS_STAMPED;
}

void
assign_fakehost(struct userNode *user, const char *host, int announce)
{
    safestrncpy(user->fakehost, host, sizeof(user->fakehost));
    if (announce)
        irc_fakehost(user, host);
}

void
set_geoip_info(struct userNode *user)
{
    if(IsLocal(user))
        return;
/* Need the libs and the headers if this is going to compile properly */
#if defined(HAVE_LIBGEOIP)&&defined(HAVE_GEOIP_H)&&defined(HAVE_GEOIPCITY_H)
    GeoIPRecord * gir;
    const char *geoip_data_file = NULL;
    const char *geoip_city_file = NULL;

    geoip_data_file = conf_get_data("services/opserv/geoip_data_file", RECDB_QSTRING);
    geoip_city_file = conf_get_data("services/opserv/geoip_city_data_file", RECDB_QSTRING);

    if ((!geoip_data_file && !geoip_city_file))
        return; /* Admin doesnt want to use geoip functions */

    if (geoip_data_file && !gi)
        gi  = GeoIP_open(geoip_data_file, GEOIP_MEMORY_CACHE | GEOIP_CHECK_CACHE);

    if (geoip_city_file && !cgi)
        cgi = GeoIP_open(geoip_city_file, GEOIP_MEMORY_CACHE | GEOIP_CHECK_CACHE);

    if (cgi) {
        gir = GeoIP_record_by_name(cgi, user->hostname);
        if (gir) {
            user->country_name = strdup(gir->country_name ? gir->country_name : "");
            user->country_code = strdup(gir->country_code ? gir->country_code : "");
            user->city         = strdup(gir->city ? gir->city : "");
            user->region       = strdup(gir->region ? gir->region : "");
            user->postal_code  = strdup(gir->postal_code ? gir->postal_code : "");

            user->latitude  = gir->latitude ? gir->latitude : 0;
            user->longitude = gir->longitude ? gir->longitude : 0;
            user->dma_code  = gir->dma_code ? gir->dma_code : 0;
            user->area_code = gir->area_code ? gir->area_code : 0;

            GeoIPRecord_delete(gir);
        }

        return;
    } else if (gi) {
        const char *country = GeoIP_country_name_by_name(gi, user->hostname);
        user->country_name = strdup(country ? country : "");
        return;
    }

    return;
#endif
}

static new_channel_func_t *ncf_list;
static void **ncf_list_extra;
static unsigned int ncf_size = 0, ncf_used = 0;

void
reg_new_channel_func(new_channel_func_t handler, void *extra)
{
    if (ncf_used == ncf_size) {
	if (ncf_size) {
	    ncf_size <<= 1;
	    ncf_list = realloc(ncf_list, ncf_size*sizeof(ncf_list[0]));
        ncf_list_extra = realloc(ncf_list_extra, ncf_size*sizeof(void*));
	} else {
	    ncf_size = 8;
	    ncf_list = malloc(ncf_size*sizeof(ncf_list[0]));
        ncf_list_extra = malloc(ncf_size*sizeof(void*));
	}
    }
    ncf_list[ncf_used] = handler;
    ncf_list_extra[ncf_used++] = extra;
}

static join_func_t *jf_list;
static void **jf_list_extra;
static unsigned int jf_size = 0, jf_used = 0;

void
reg_join_func(join_func_t handler, void *extra)
{
    if (jf_used == jf_size) {
	if (jf_size) {
	    jf_size <<= 1;
	    jf_list = realloc(jf_list, jf_size*sizeof(join_func_t));
        jf_list_extra = realloc(jf_list_extra, jf_size*sizeof(void*));
	} else {
	    jf_size = 8;
	    jf_list = malloc(jf_size*sizeof(join_func_t));
        jf_list_extra = malloc(jf_size*sizeof(void*));
	}
    }
    jf_list[jf_used] = handler;
    jf_list_extra[jf_used++] = extra;
}

int rel_age;

static void
wipeout_channel(struct chanNode *cNode, time_t new_time, char **modes, unsigned int modec) {
    unsigned int orig_limit;
    chan_mode_t orig_modes;
    char orig_key[KEYLEN+1];
    char orig_apass[KEYLEN+1];
    char orig_upass[KEYLEN+1];
    unsigned int nn, argc;

    /* nuke old topic */
    cNode->topic[0] = '\0';
    cNode->topic_nick[0] = '\0';
    cNode->topic_time = 0;

    /* remember the old modes, and update them with the new */
    orig_modes = cNode->modes;
    orig_limit = cNode->limit;
    strcpy(orig_key, cNode->key);
    strcpy(orig_upass, cNode->upass);
    strcpy(orig_apass, cNode->apass);
    cNode->modes = 0;
    mod_chanmode(NULL, cNode, modes, modec, 0);
    cNode->timestamp = new_time;

    /* remove our old ban list, replace it with the new one */
    for (nn=0; nn<cNode->banlist.used; nn++)
        free(cNode->banlist.list[nn]);
    cNode->banlist.used = 0;

    /* remove our old exe,[t list, replace it with the new one */
    for (nn=0; nn<cNode->exemptlist.used; nn++)
        free(cNode->exemptlist.list[nn]);
    cNode->exemptlist.used = 0;

    /* deop anybody in the channel now, but count services to reop */
    for (nn=argc=0; nn<cNode->members.used; nn++) {
        struct modeNode *mn = cNode->members.list[nn];
        if ((mn->modes & MODE_CHANOP) && IsService(mn->user) && IsLocal(mn->user))
            argc++;
    }

    if (argc) {
        struct mod_chanmode *change;

        change = mod_chanmode_alloc(argc);
        change->modes_clear = 0;
        change->modes_set = orig_modes;
        change->new_limit = orig_limit;
        strcpy(change->new_key, orig_key);
        strcpy(change->new_upass, orig_upass);
        strcpy(change->new_apass, orig_apass);
        for (nn = argc = 0; nn < cNode->members.used; ++nn) {
            struct modeNode *mn = cNode->members.list[nn];
            if ((mn->modes & MODE_CHANOP) && IsService(mn->user) && IsLocal(mn->user)) {
                change->args[argc].mode = MODE_CHANOP;
                change->args[argc].u.member = mn;
                argc++;
            }
        }
        assert(argc == change->argc);
        change->args[0].u.member->modes &= ~MODE_CHANOP;
        mod_chanmode_announce(change->args[0].u.member->user, cNode, change);
        mod_chanmode_free(change);
    }
}

struct chanNode *
AddChannel(const char *name, time_t time_, const char *modes, char *banlist, char *exemptlist)
{
    struct chanNode *cNode;
    char new_modes[MAXLEN], *argv[MAXNUMPARAMS];
    unsigned int nn;

    if (!IsChannelName(name)) {
        log_module(MAIN_LOG, LOG_ERROR, "Somebody asked to add channel '%s', which isn't a channel name!", name);
        return NULL;
    }
    if (!modes)
        modes = "";

    safestrncpy(new_modes, modes, sizeof(new_modes));
    nn = split_line(new_modes, 0, ArrayLength(argv), argv);
    if (!(cNode = GetChannel(name))) {
        cNode = calloc(1, sizeof(*cNode) + strlen(name));
        strcpy(cNode->name, name);
        banList_init(&cNode->banlist);
        exemptList_init(&cNode->exemptlist);
        modeList_init(&cNode->members);
        mod_chanmode(NULL, cNode, argv, nn, MCP_FROM_SERVER);
        dict_insert(channels, cNode->name, cNode);
        cNode->timestamp = time_;
        rel_age = 1;
    } else if (cNode->timestamp > time_) {
        wipeout_channel(cNode, time_, argv, nn);
        rel_age = 1;
    } else if (cNode->timestamp == time_) {
        mod_chanmode(NULL, cNode, argv, nn, MCP_FROM_SERVER);
        rel_age = 0;
    } else {
        rel_age = -1;
    }

    /* rel_age is the relative ages of our channel data versus what is
     * in a BURST command.  1 means ours is younger, 0 means both are
     * the same age, -1 means ours is older. */

    /* if it's a new or updated channel, make callbacks */
    if (rel_age > 0)
        for (nn=0; nn<ncf_used; nn++)
            ncf_list[nn](cNode, ncf_list_extra[nn]);

    /* go through list of bans and add each one */
    if (banlist && (rel_age >= 0)) {
        for (nn=0; banlist[nn];) {
            char *ban = banlist + nn;
            struct banNode *bn;
            while (banlist[nn] != ' ' && banlist[nn])
                nn++;
            while (banlist[nn] == ' ')
                banlist[nn++] = 0;
            bn = calloc(1, sizeof(*bn));
            safestrncpy(bn->ban, ban, sizeof(bn->ban));
            safestrncpy(bn->who, "<unknown>", sizeof(bn->who));
            bn->set = now;
            banList_append(&cNode->banlist, bn);
        }
    }

    /* go through list of exempts and add each one */
    if (exemptlist && (rel_age >= 0)) {
        for (nn=0; exemptlist[nn];) {
            char *exempt = exemptlist + nn;
            struct exemptNode *en;
            while (exemptlist[nn] != ' ' && exemptlist[nn])
                nn++;
            while (exemptlist[nn] == ' ')
                exemptlist[nn++] = 0;
            en = calloc(1, sizeof(*en));
            safestrncpy(en->exempt, exempt, sizeof(en->exempt));
            safestrncpy(en->who, "<unknown>", sizeof(en->who));
            en->set = now;
            exemptList_append(&cNode->exemptlist, en);
        }
    }

    return cNode;
}

static del_channel_func_t *dcf_list;
static void **dcf_list_extra;
static unsigned int dcf_size = 0, dcf_used = 0;

void
reg_del_channel_func(del_channel_func_t handler, void *extra)
{
    if (dcf_used == dcf_size) {
	if (dcf_size) {
	    dcf_size <<= 1;
	    dcf_list = realloc(dcf_list, dcf_size*sizeof(dcf_list[0]));
        dcf_list_extra = realloc(dcf_list_extra, dcf_size*sizeof(void*));
	} else {
	    dcf_size = 8;
	    dcf_list = malloc(dcf_size*sizeof(dcf_list[0]));
        dcf_list_extra = malloc(dcf_size*sizeof(dcf_list_extra[0]));
	}
    }
    dcf_list[dcf_used] = handler;
    dcf_list_extra[dcf_used++] = extra;
}

static void
DelChannel(struct chanNode *channel)
{
    unsigned int n;

    verify(channel);
    dict_remove(channels, channel->name);

    if (channel->members.used || channel->locks) {
        log_module(MAIN_LOG, LOG_ERROR, "Warning: deleting channel %s with %d users and %d locks remaining.", channel->name, channel->members.used, channel->locks);
    }

    /* go through all channel members and delete them from the channel */
    for (n=channel->members.used; n>0; )
	DelChannelUser(channel->members.list[--n]->user, channel, NULL, 1);

    /* delete all channel bans */
    for (n=channel->banlist.used; n>0; )
        free(channel->banlist.list[--n]);
    channel->banlist.used = 0;

    /* delete all channel exempts */
    for (n=channel->exemptlist.used; n>0; )
        free(channel->exemptlist.list[--n]);
    channel->exemptlist.used = 0;

    for (n=0; n<dcf_used; n++)
        dcf_list[n](channel, dcf_list_extra[n]);

    modeList_clean(&channel->members);
    banList_clean(&channel->banlist);
    exemptList_clean(&channel->exemptlist);
    free(channel);
}

struct modeNode *
AddChannelUser(struct userNode *user, struct chanNode* channel)
{
	struct modeNode *mNode;
	unsigned int n;

	mNode = GetUserMode(channel, user);
	if (mNode)
            return mNode;

	mNode = malloc(sizeof(*mNode));

	/* set up modeNode */
	mNode->channel = channel;
	mNode->user = user;
	mNode->modes = 0;
        mNode->oplevel = -1;
        mNode->idle_since = now;

	/* Add modeNode to channel and to user.
         * We have to do this before calling join funcs in case the
         * modeNode is manipulated (e.g. chanserv ops the user).
         */
	modeList_append(&channel->members, mNode);
	modeList_append(&user->channels, mNode);

        if (channel->members.used == 1
            && !(channel->modes & MODE_REGISTERED)
            && !(channel->modes & MODE_APASS)) {
            mNode->modes |= MODE_CHANOP;
            log_module(MAIN_LOG, LOG_DEBUG, "setting op");
        }

        if (IsLocal(user)) {
            irc_join(user, channel);
        }

        for (n=0; (n<jf_used) && !user->dead; n++) {
            /* Callbacks return true if they kick or kill the user,
             * and we can continue without removing mNode. */
            if (jf_list[n](mNode, jf_list_extra[n]))
                return NULL;
        }

	return mNode;
}

static part_func_t *pf_list;
static void **pf_list_extra;
static unsigned int pf_size = 0, pf_used = 0;

void
reg_part_func(part_func_t handler, void *extra)
{
    if (pf_used == pf_size) {
	if (pf_size) {
	    pf_size <<= 1;
	    pf_list = realloc(pf_list, pf_size*sizeof(part_func_t));
        pf_list_extra = realloc(pf_list_extra, pf_size*sizeof(void*));
	} else {
	    pf_size = 8;
	    pf_list = malloc(pf_size*sizeof(part_func_t));
        pf_list_extra = malloc(pf_size*sizeof(void*));
	}
    }
    pf_list[pf_used] = handler;
    pf_list_extra[pf_used++] = extra;
}

void
unreg_part_func(part_func_t handler, void *extra)
{
    unsigned int i;
    for (i=0; i<pf_used; i++)
        if (pf_list[i] == handler && pf_list_extra[i] == extra)
            break;
    if (i == pf_used)
        return;
    memmove(pf_list+i, pf_list+i+1, (pf_used-i-1)*sizeof(pf_list[0]));
    memmove(pf_list_extra+i, pf_list_extra+i+1, (pf_used-i-1)*sizeof(pf_list_extra[0]));
    pf_used--;
}

void
LockChannel(struct chanNode* channel)
{
    channel->locks++;
}

void
UnlockChannel(struct chanNode *channel)
{
    assert(channel->locks > 0);
    if (!--channel->locks && !channel->members.used)
        DelChannel(channel);
}

void
DelChannelUser(struct userNode* user, struct chanNode* channel, const char *reason, int deleting)
{
    struct modeNode* mNode;
    unsigned int n;

    if (IsLocal(user) && reason)
        irc_part(user, channel, reason);

    mNode = GetUserMode(channel, user);

    /* Sometimes we get a PART when the user has been KICKed.
     * In this case, we get no usermode, and should not try to free it.
     */
    if (!mNode)
        return;

    /* remove modeNode from channel and user */
    modeList_remove(&channel->members, mNode);
    modeList_remove(&user->channels, mNode);

    /* make callbacks */
    for (n=0; n<pf_used; n++)
	pf_list[n](mNode, reason, pf_list_extra[n]);

    /* free memory */
    free(mNode);

    /* A single check for APASS only should be enough here */
    if (!deleting && !channel->members.used && !channel->locks
        && !(channel->modes & MODE_REGISTERED) && !(channel->modes & MODE_APASS))
        DelChannel(channel);
}

static kick_func_t *kf_list;
static void **kf_list_extra;
static unsigned int kf_size = 0, kf_used = 0;

void
KickChannelUser(struct userNode* target, struct chanNode* channel, struct userNode *kicker, const char *why)
{
    unsigned int n;

    if (!target || !channel || IsService(target) || !GetUserMode(channel, target))
        return;

    /* This may break things, but lets see.. -Rubin */
    for (n=0; n<kf_used; n++)
        kf_list[n](kicker, target, channel, kf_list_extra[n]);

    /* don't remove them from the channel, since the server will send a PART */
    irc_kick(kicker, target, channel, why);

    if (IsLocal(target))
    {
	/* NULL reason because we don't want a PART message to be
	   sent by DelChannelUser. */
	DelChannelUser(target, channel, NULL, 0);
    }
}

void
reg_kick_func(kick_func_t handler, void *extra)
{
    if (kf_used == kf_size) {
	if (kf_size) {
	    kf_size <<= 1;
	    kf_list = realloc(kf_list, kf_size*sizeof(kick_func_t));
        kf_list_extra = realloc(kf_list_extra, kf_size*sizeof(void*));
	} else {
	    kf_size = 8;
	    kf_list = malloc(kf_size*sizeof(kick_func_t));
        kf_list_extra = malloc(kf_size*sizeof(void*));
	}
    }
    kf_list[kf_used] = handler;
    kf_list_extra[kf_used++] = extra;
}

void
ChannelUserKicked(struct userNode* kicker, struct userNode* victim, struct chanNode* channel)
{
    unsigned int n;
    struct modeNode *mn;

    if (!victim || !channel || !GetUserMode(channel, victim))
        return;

    /* Update the kicker's idle time (kicker may be null if it was a server) */
    if (kicker && (mn = GetUserMode(channel, kicker)))
        mn->idle_since = now;

    for (n=0; n<kf_used; n++)
	kf_list[n](kicker, victim, channel, kf_list_extra[n]);

    DelChannelUser(victim, channel, 0, 0);

    if (IsLocal(victim))
	irc_part(victim, channel, NULL);
}

int ChannelBanExists(struct chanNode *channel, const char *ban)
{
    unsigned int n;

    for (n = 0; n < channel->banlist.used; n++)
	if (match_ircglobs(channel->banlist.list[n]->ban, ban))
	    return 1;
    return 0;
}

int ChannelExemptExists(struct chanNode *channel, const char *exempt)
{
    unsigned int n;

    for (n = 0; n < channel->exemptlist.used; n++)
        if (match_ircglobs(channel->exemptlist.list[n]->exempt, exempt))
            return 1;
    return 0;
}

static topic_func_t *tf_list;
static void **tf_list_extra;
static unsigned int tf_size = 0, tf_used = 0;

void
reg_topic_func(topic_func_t handler, void *extra)
{
    if (tf_used == tf_size) {
	if (tf_size) {
	    tf_size <<= 1;
	    tf_list = realloc(tf_list, tf_size*sizeof(topic_func_t));
        tf_list_extra = realloc(tf_list_extra, tf_size*sizeof(void*));
	} else {
	    tf_size = 8;
	    tf_list = malloc(tf_size*sizeof(topic_func_t));
        tf_list_extra = malloc(tf_size*sizeof(void*));
	}
    }
    tf_list[tf_used] = handler;
    tf_list_extra[tf_used++] = extra;
}

void
SetChannelTopic(struct chanNode *channel, struct userNode *service, struct userNode *user, const char *topic, int announce)
{
    unsigned int n;
    struct modeNode *mn;
    char old_topic[TOPICLEN+1];

    safestrncpy(old_topic, channel->topic, sizeof(old_topic));
    safestrncpy(channel->topic, topic, sizeof(channel->topic));
    channel->topic_time = now;

    if (user) {
        safestrncpy(channel->topic_nick, user->nick, sizeof(channel->topic_nick));

        /* Update the setter's idle time */
        if ((mn = GetUserMode(channel, user)))
            mn->idle_since = now;
    }

    if (announce) {
	/* We don't really care if a local user messes with the topic,
         * so don't call the tf_list functions. */
	irc_topic(service, user, channel, topic);
    } else {
	for (n=0; n<tf_used; n++)
            /* A topic change handler can return non-zero to indicate
             * that it has reverted the topic change, and that further
             * hooks should not be called.
             */
	    if (tf_list[n](user, channel, old_topic, tf_list_extra[n]))
                break;
    }
}

struct chanNode *
GetChannel(const char *name)
{
    return dict_find(channels, name, NULL);
}

struct modeNode *
GetUserMode(struct chanNode *channel, struct userNode *user)
{
    unsigned int n;
    struct modeNode *mn = NULL;

    verify(channel);
    verify(channel->members.list);
    verify(user);
    verify(user->channels.list);
    if (channel->members.used < user->channels.used) {
	for (n=0; n<channel->members.used; n++) {
            verify(channel->members.list[n]);
	    if (user == channel->members.list[n]->user) {
		mn = channel->members.list[n];
		break;
	    }
	}
    } else {
	for (n=0; n<user->channels.used; n++) {
            verify(user->channels.list[n]);
	    if (channel == user->channels.list[n]->channel) {
		mn = user->channels.list[n];
		break;
	    }
	}
    }
    return mn;
}

struct userNode *IsInChannel(struct chanNode *channel, struct userNode *user)
{
    unsigned int n;

    verify(channel);
    verify(channel->members.list);
    verify(user);
    verify(user->channels.list);
    if (channel->members.used < user->channels.used) {
	for (n=0; n<channel->members.used; n++) {
            verify(channel->members.list[n]);
	    if (user == channel->members.list[n]->user) {
                return(user);
	    }
	}
    } else {
	for (n=0; n<user->channels.used; n++) {
            verify(user->channels.list[n]);
	    if (channel == user->channels.list[n]->channel) {
                return(user);
	    }
	}
    }
    return NULL;
}

DEFINE_LIST(userList, struct userNode*)
DEFINE_LIST(modeList, struct modeNode*)
DEFINE_LIST(banList, struct banNode*)
DEFINE_LIST(exemptList, struct exemptNode*)
DEFINE_LIST(channelList, struct chanNode*)
DEFINE_LIST(serverList, struct server*)

static void
hash_cleanup(void)
{
    dict_iterator_t it, next;

    DelServer(self, 0, NULL);
    for (it = dict_first(channels); it; it = next) {
        next = iter_next(it);
        DelChannel(iter_data(it));
    }
    dict_delete(channels);
    dict_delete(clients);
    dict_delete(servers);
    userList_clean(&curr_opers);

    free(slf_list);
    free(slf_list_extra);
    free(nuf_list);
    free(nuf_list_extra);
    free(ncf2_list);
    free(ncf2_list_extra);
    free(duf_list);
    free(duf_list_extra);
    free(ncf_list);
    free(ncf_list_extra);
    free(jf_list);
    free(jf_list_extra);
    free(dcf_list);
    free(dcf_list_extra);
    free(pf_list);
    free(pf_list_extra);
    free(kf_list);
    free(kf_list_extra);
    free(tf_list);
    free(tf_list_extra);
}
