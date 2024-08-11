/* hash.h - IRC network state database
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

#ifndef HASH_H
#define HASH_H

#include "common.h"
#include "dict.h"
#include "eventhooks.h"
#include "policer.h"
#include "recdb.h"

#define MODE_CHANOP		0x00000001 /* +o USER */
#define MODE_VOICE		0x00000002 /* +v USER */
#define MODE_PRIVATE		0x00000004 /* +p */
#define MODE_SECRET		0x00000008 /* +s */
#define MODE_MODERATED		0x00000010 /* +m */
#define MODE_TOPICLIMIT		0x00000020 /* +t */
#define MODE_INVITEONLY		0x00000040 /* +i */
#define MODE_NOPRIVMSGS		0x00000080 /* +n */
#define MODE_KEY		0x00000100 /* +k KEY */
#define MODE_BAN		0x00000200 /* +b BAN */
#define MODE_LIMIT		0x00000400 /* +l LIMIT */
#define MODE_DELAYJOINS         0x00000800 /* +D */
#define MODE_REGONLY            0x00001000 /* ircu +r */
#define MODE_NOCOLORS           0x00002000 /* +c */
#define MODE_NOCTCPS            0x00004000 /* +C */
#define MODE_REGISTERED         0x00008000 /* Bahamut +r */
#define MODE_STRIPCOLOR         0x00010000 /* +S Strip mirc color codes */
#define MODE_MODUNREG           0x00020000 /* +M mod unregister */
#define MODE_NONOTICE           0x00040000 /* +N no notices */
#define MODE_OPERSONLY          0x00080000 /* +O Opers only */
#define MODE_NOQUITMSGS         0x00100000 /* +Q suppress messages from quit notices */
#define MODE_NOAMSG             0x00200000 /* +T no multi-target messages */
#define MODE_SSLONLY            0x00400000 /* +Z ssl only */
#define MODE_HALFOP             0x00800000 /* +h USER */
#define MODE_EXEMPT             0x01000000 /* +e exempt */
#define MODE_HIDEMODE		0x02000000 /* +L hide modes */
#define MODE_APASS		0x04000000 /* +A adminpass */
#define MODE_UPASS		0x08000000 /* +U userpass */
#define MODE_ADMINSONLY         0x10000000 /* +a Admins only */
#define MODE_REMOVE             0x80000000

#define FLAGS_OPER		0x00000001 /* Operator +o */
#define FLAGS_LOCOP		0x00000002 /* Local operator +O */
#define FLAGS_INVISIBLE		0x00000004 /* invisible +i */
#define FLAGS_WALLOP		0x00000008 /* receives wallops +w */
#define FLAGS_DUMMY             0x00000010 /* user is not announced to other servers */
#define FLAGS_DEAF		0x00000020 /* deaf +d */
#define FLAGS_SERVICE		0x00000040 /* cannot be kicked, killed or deoped +k */
#define FLAGS_GLOBAL		0x00000080 /* receives global messages +g */
#define FLAGS_SETHOST		0x00000100 /* sethost +h */
#define FLAGS_PERSISTENT	0x00000200 /* for reserved nicks, this isn't just one-shot */
#define FLAGS_GAGGED		0x00000400 /* for gagged users */
#define FLAGS_AWAY		0x00000800 /* for away users */
#define FLAGS_STAMPED           0x00001000 /* for users who have been stamped */
#define FLAGS_HIDDEN_HOST       0x00002000 /* user's host is masked by their account +x */
#define FLAGS_REGNICK           0x00004000 /* user owns their current nick */
#define FLAGS_REGISTERING	0x00008000 /* user has issued account register command, is waiting for email cookie */
#define FLAGS_BOT		0x00010000 /* Bot +B */
#define FLAGS_HIDECHANS		0x00020000 /* Hidden channels +n */
#define FLAGS_HIDEIDLE		0x00040000 /* Hidden idle time +I */
#define FLAGS_XTRAOP		0x00080000 /* user is XtraOP +X */
#define FLAGS_CLOAKHOST         0x00100000 /* user has cloaked host +C */
#define FLAGS_CLOAKIP           0x00200000 /* user has cloaked ip +c */
#define FLAGS_ADMIN             0x00400000 /* Admin +a */
#define FLAGS_SSL               0x00800000 /* user is using a secure connection +z */
#define FLAGS_PRIVDEAF          0x01000000 /* user is deaf to private messages +D */
#define FLAGS_ACCOUNTONLY       0x02000000 /* user only receives PMs from authed users +R */
#define FLAGS_WHOIS             0x04000000 /* user receives notices when /whois'ed +W */
#define FLAGS_HIDEOPER          0x08000000 /* user is a hidden IRCop +H */
#define FLAGS_NOLINK            0x10000000 /* user has opted out of channel redirection +L */
#define FLAGS_COMMONCHANSONLY   0x20000000 /* user only receives PMs from users on same cahnnels +q */

#define IsOper(x)               ((x)->modes & FLAGS_OPER)
#define IsService(x)            ((x)->modes & FLAGS_SERVICE)
#define IsDeaf(x)               ((x)->modes & FLAGS_DEAF)
#define IsInvisible(x)          ((x)->modes & FLAGS_INVISIBLE)
#define IsGlobal(x)             ((x)->modes & FLAGS_GLOBAL)
#define IsWallOp(x)             ((x)->modes & FLAGS_WALLOP)
#define IsBotM(x)      		((x)->modes & FLAGS_BOT)
#define IsHideChans(x)   	((x)->modes & FLAGS_HIDECHANS)
#define IsHideIdle(x)      	((x)->modes & FLAGS_HIDEIDLE)
#define IsXtraOp(x)		((x)->modes & FLAGS_XTRAOP)
#define IsSetHost(x)		((x)->modes & FLAGS_SETHOST)
#define IsGagged(x)             ((x)->modes & FLAGS_GAGGED)
#define IsPersistent(x)         ((x)->modes & FLAGS_PERSISTENT) 
#define IsAway(x)               ((x)->modes & FLAGS_AWAY)
#define IsStamped(x)            ((x)->modes & FLAGS_STAMPED)
#define IsHiddenHost(x)         ((x)->modes & FLAGS_HIDDEN_HOST)
#define IsReggedNick(x)         ((x)->modes & FLAGS_REGNICK)
#define IsRegistering(x)	((x)->modes & FLAGS_REGISTERING)
#define IsDummy(x)              ((x)->modes & FLAGS_DUMMY)
#define IsFakeHost(x)           ((x)->fakehost[0] != '\0')
#define IsLocal(x)              ((x)->uplink == self)
#define IsAdmin(x)              ((x)->modes & FLAGS_ADMIN)
#define IsSSL(x)                ((x)->modes & FLAGS_SSL)
#define IsPrivDeaf(x)           ((x)->modes & FLAGS_PRIVDEAF)
#define IsAccountOnly(x)        ((x)->modes & FLAGS_ACCOUNTONLY)
#define IsWhoisNotice(x)        ((x)->modes & FLAGS_WHOIS)
#define IsHideOper(x)           ((x)->modes & FLAGS_HIDEOPER)
#define IsNoRedirect(x)         ((x)->modes & FLAGS_NOLINK)
#define IsCommonChansOnly(x)    ((x)->modes & FLAGS_COMMONCHANSONLY)

#define NICKLEN         30
#define USERLEN         10
#define HOSTLEN         75
#define SOCKIPLEN       45
#define ACCOUNTLEN      15
#define REALLEN         50
#define TOPICLEN        250
#define CHANNELLEN      200
#define MARKLEN         200
#define MAXOPLEVEL      999

#define MAXMODEPARAMS	6
#define MAXBANS		128
#define MAXEXEMPTS	45

/* IDLEN is 6 because it takes 5.33 Base64 digits to store 32 bytes. */
#define IDLEN           6

/** Operator privileges. */
enum Priv {
  PRIV_CHAN_LIMIT,      /**< no channel limit on oper */
  PRIV_MODE_LCHAN,      /**< oper can mode local chans */
  PRIV_WALK_LCHAN,      /**< oper can walk through local modes */
  PRIV_DEOP_LCHAN,      /**< no deop oper on local chans */
  PRIV_SHOW_INVIS,      /**< show local invisible users */
  PRIV_SHOW_ALL_INVIS,  /**< show all invisible users */
  PRIV_UNLIMIT_QUERY,   /**< unlimit who queries */
  PRIV_KILL,            /**< oper can KILL */
  PRIV_LOCAL_KILL,      /**< oper can local KILL */
  PRIV_REHASH,          /**< oper can REHASH */
  PRIV_REMOTEREHASH,    /**< oper can remote REHASH */
  PRIV_RESTART,         /**< oper can RESTART */
  PRIV_DIE,             /**< oper can DIE */
  PRIV_ZLINE,           /**< oper can ZLINE */
  PRIV_LOCAL_ZLINE,     /**< oper can local ZLINE */
  PRIV_GLINE,           /**< oper can GLINE */
  PRIV_LOCAL_GLINE,     /**< oper can local GLINE */
  PRIV_SHUN,            /**< oper can SHUN */
  PRIV_LOCAL_SHUN,      /**< oper can local SHUN */
  PRIV_JUPE,            /**< oper can JUPE */
  PRIV_LOCAL_JUPE,      /**< oper can local JUPE */
  PRIV_OPMODE,          /**< oper can OP/CLEARMODE */
  PRIV_LOCAL_OPMODE,    /**< oper can local OP/CLEARMODE */
  PRIV_SET,             /**< oper can SET */
  PRIV_WHOX,            /**< oper can use /who x */
  PRIV_BADCHAN,         /**< oper can BADCHAN */
  PRIV_LOCAL_BADCHAN,   /**< oper can local BADCHAN */
  PRIV_SEE_CHAN,        /**< oper can see in secret chans */
  PRIV_PROPAGATE,       /**< propagate oper status */
  PRIV_DISPLAY,         /**< "Is an oper" displayed */
  PRIV_DISPLAY_MODE,    /**< oper can set +H hide oper */
  PRIV_SEE_OPERS,       /**< display hidden opers */
  PRIV_WIDE_GLINE,      /**< oper can set wider G-lines */
  PRIV_WIDE_ZLINE,      /**< oper can set wider Z-Lines */
  PRIV_WIDE_SHUN,       /**< oper can set wider G-lines */
  PRIV_LIST_CHAN,       /**< oper can list secret channels */
  PRIV_FORCE_OPMODE,    /**< can hack modes on quarantined channels */
  PRIV_FORCE_LOCAL_OPMODE, /**< can hack modes on quarantined local channels */
  PRIV_CHECK,           /**< oper can use CHECK */
  PRIV_SEE_SECRET_CHAN, /**< oper can see +s channels in whois */
  PRIV_WHOIS_NOTICE,    /**< oper can set/unset user mode +W */
  PRIV_HIDE_IDLE,       /**< oper can set/unset user mode +I */
  PRIV_XTRAOP,          /**< oper can set/unset user mode +X */
  PRIV_HIDE_CHANNELS,   /**< oper can set/unset user mode +n */
  PRIV_FREEFORM,        /**< oper can set any host on themseves using set host
                              as long as its a valid host */
  PRIV_REMOVE,          /**< oper can force remove deactivated glines,
                             shuns and zlines. */
  PRIV_SPAMFILTER,      /**< oper can set spamfilters via SPAMFILTER */
  PRIV_ADMIN,           /**< oper is an IRC Admin */
  PRIV_APASS_OPMODE,    /**< oper can use OPMODE to set/unset channel modes +A and +U */
  PRIV_HIDE_OPER,       /**< oper can set/unset user mode +H */
  PRIV_REMOTE,          /**< oper can use his/her operator block from a remote server */
  PRIV_SERVICE,         /**< oper can set/unset user mode +k */
  PRIV_LAST_PRIV        /**< number of privileges */
};

/** Number of bits */
#define _PRIV_NBITS             (8 * sizeof(unsigned long))
/** Element number for priv \a priv. */
#define _PRIV_IDX(priv)         ((priv) / _PRIV_NBITS)
/** Element bit for priv \a priv. */
#define _PRIV_BIT(priv)         (1UL << ((priv) % _PRIV_NBITS))

/** Operator privileges. */
struct Privs {
  unsigned long priv_mask[(PRIV_LAST_PRIV + _PRIV_NBITS - 1) / _PRIV_NBITS];
};

DECLARE_LIST(userList, struct userNode*);
DECLARE_LIST(modeList, struct modeNode*);
DECLARE_LIST(banList, struct banNode*);
DECLARE_LIST(exemptList, struct exemptNode*);
DECLARE_LIST(channelList, struct chanNode*);
DECLARE_LIST(serverList, struct server*);

struct userNode {
    char *nick;                   /* Unique name of the client, nick or host */
    char ident[USERLEN + 1];      /* Per-host identification for user */
    char info[REALLEN + 1];       /* Free form additional client information */
    char hostname[HOSTLEN + 1];   /* DNS name or IP address */
    char fakehost[HOSTLEN + 1];   /* Assigned fake host */
    char crypthost[HOSTLEN + 30]; /* Crypted hostname */
    char cryptip[SOCKIPLEN + 30]; /* Crypted IP */
#ifdef WITH_PROTOCOL_P10
    char numeric[COMBO_NUMERIC_LEN+1];
    unsigned int num_local : 18;
#endif
    unsigned int loc;             /* Is user connecting via LOC? */
    unsigned int no_notice;       /* Does the users client not see notices? */
    unsigned int dead : 1;        /* Is user waiting to be recycled? */
    irc_in_addr_t ip;             /* User's IP address */
    long modes;                   /* user flags +isw etc... */

    // sethost - reed/apples
    char sethost[USERLEN + HOSTLEN + 2]; /* 1 for '\0' and 1 for @ = 2 */

    /* GeoIP Data */
    char *country_name;

    /* GeoIP City Data */
    char *country_code;
    char *city;
    char *region;
    char *postal_code;
    float latitude;
    float longitude;
    int dma_code;
    int area_code;
    
    char *mark;                   /* only filled if they are marked */
    char *version_reply;          /* only filled in if a version query was triggered */
    char *sslfp;                  /* only filled in if a mark SSLCLIFP is received */

    struct string_list *marks;    /* list of user's marks */

    time_t timestamp;             /* Time of last nick change */
    time_t idle_since;
    struct server *uplink;        /* Server that user is connected to */
    struct modeList channels;     /* Vector of channels user is in */
    struct Privs   privs;

    /* from nickserv */
    struct handle_info *handle_info;
    struct userNode *next_authed;
    struct policer auth_policer;
};

#define privs(cli)             ((cli)->privs)
#define PrivSet(pset, priv)     ((pset)->priv_mask[_PRIV_IDX(priv)] |= \
                                 _PRIV_BIT(priv))
#define PrivClr(pset, priv)     ((pset)->priv_mask[_PRIV_IDX(priv)] &= \
                                 ~(_PRIV_BIT(priv)))
#define PrivHas(pset, priv)     ((pset)->priv_mask[_PRIV_IDX(priv)] & \
                                 _PRIV_BIT(priv))

#define PRIV_ADD 1
#define PRIV_DEL 0

#define GrantPriv(cli, priv)    (PrivSet(&(privs(cli)), priv))
#define RevokePriv(cli, priv)   (PrivClr(&(privs(cli)), priv))
#define HasPriv(cli, priv)      (PrivHas(&(privs(cli)), priv))

struct chanNode {
    chan_mode_t modes;
    unsigned int limit, locks;
    char key[KEYLEN + 1];
    char upass[KEYLEN + 1];
    char apass[KEYLEN + 1];
    time_t timestamp; /* creation time */
  
    char topic[TOPICLEN + 1];
    char topic_nick[NICKLEN + 1];
    time_t topic_time;

    struct modeList members;
    struct banList banlist;
    struct exemptList exemptlist;
    struct policer join_policer;
    unsigned int join_flooded : 1;
    unsigned int bad_channel : 1;

    struct chanData *channel_info;
    struct channel_help *channel_help;
    char name[1];
};

struct banNode {
    char ban[NICKLEN + USERLEN + HOSTLEN + 3]; /* 1 for '\0', 1 for ! and 1 for @ = 3 */
    char who[NICKLEN + 1]; /* who set ban */
    time_t set; /* time ban was set */
};

struct exemptNode {
    char exempt[NICKLEN + USERLEN + HOSTLEN + 3]; /* 1 for '\0', 1 for ! and 1 for @ = 3 */
    char who[NICKLEN + 1]; /* who set exempt */
    time_t set; /* time exempt was set */
};

struct modeNode {
    struct chanNode *channel;
    struct userNode *user;
    long modes;
    short oplevel;
    time_t idle_since;
};

#define SERVERNAMEMAX 64
#define SERVERDESCRIPTMAX 128

struct server {
    char name[SERVERNAMEMAX+1];
    time_t boot;
    time_t link_time;
    char description[SERVERDESCRIPTMAX+1];
#ifdef WITH_PROTOCOL_P10
    char numeric[COMBO_NUMERIC_LEN+1];
    unsigned int num_mask;
#endif
    unsigned int hops, clients, max_clients;
    unsigned int burst : 1, self_burst : 1;
    struct server *uplink;
#ifdef WITH_PROTOCOL_P10
    struct userNode **users; /* flat indexed by numeric */
#else
    dict_t users; /* indexed by nick */
#endif
    struct serverList children;
};

struct waitingConnection {
    char *server;
    char *target;
};

struct routingPlan {
    dict_t servers;
};

struct routingPlanServer {
    char *uplink;
    char *secondaryuplink;
    unsigned int port;
    int karma;
    int offline;
};

/* Ported from X2 */
struct routeList {
    char* server;              /* Name of the server */
    unsigned int   port;       /* connection port */
    char *uplink;              /* Server its linked to (towards us) */
    char *secondaryuplink; 
    int outsideness;           /* 0 means leaf, 1 second layer, etc. my uplink is highest */
    struct routeList *next;
};

/* Ported from X2 */
struct route {
    int count;                 /* how many servers we have */
    int maxdepth;              /* biggest outsideness value */
    int centered;              /* set to TRUE when changerouteUplinks is run */
    struct routeList *servers;
};

/* generic hook function args */
struct funcargs {
    void *func;
    void *extra;
};

extern struct server *self;
extern dict_t channels;
extern dict_t clients;
extern dict_t servers;
extern unsigned int max_clients, invis_clients;
extern time_t max_clients_time;
extern struct userList curr_opers, curr_helpers;

extern unsigned int count_opers;

struct server* GetServerH(const char *name); /* using full name */
struct userNode* GetUserH(const char *nick);   /* using nick */
struct chanNode* GetChannel(const char *name);
struct modeNode* GetUserMode(struct chanNode* channel, struct userNode* user);
int userList_contains(struct userList *list, struct userNode *user);
unsigned int IsUserP(struct userNode *user);

typedef int (*server_link_func_t) (struct server *server, void *extra);
void reg_server_link_func(server_link_func_t handler, void *extra);
void call_server_link_funcs(struct server *server);

typedef void (*sasl_input_func_t) (struct server* source ,const char *identifier, const char *subcmd, const char *data, const char *ext, void *extra);
void reg_sasl_input_func(sasl_input_func_t handler, void *extra);
void call_sasl_input_func(struct server* source ,const char *identifier, const char *subcmd, const char *data, const char *ext);
void unreg_sasl_input_func(sasl_input_func_t handler, void *extra);

typedef int (*new_user_func_t) (struct userNode *user, void *extra);
void reg_new_user_func(new_user_func_t handler, void *extra);
void reg_new_user_func_pos(new_user_func_t handler, void *extra, int pos);
void call_new_user_funcs(struct userNode *user);
typedef void (*del_user_func_t) (struct userNode *user, struct userNode *killer, const char *why, void *extra);
void reg_del_user_func(del_user_func_t handler, void *extra);
void call_del_user_funcs(struct userNode *user, struct userNode *killer, const char *why);
void unreg_del_user_func(del_user_func_t handler, void *extra);
void ReintroduceUser(struct userNode* user);
typedef void (*nick_change_func_t)(struct userNode *user, const char *old_nick, void *extra);
void reg_nick_change_func(nick_change_func_t handler, void *extra);
void NickChange(struct userNode* user, const char *new_nick, int no_announce);
void SVSNickChange(struct userNode* user, const char *new_nick);

typedef void (*account_func_t) (struct userNode *user, const char *stamp);
void reg_account_func(account_func_t handler);
void call_account_func(struct userNode *user, const char *stamp);
void StampUser(struct userNode *user, const char *stamp, time_t timestamp);
void assign_fakehost(struct userNode *user, const char *host, int announce);
void set_geoip_info(struct userNode *user);

typedef void (*new_channel_func_t) (struct chanNode *chan, void *extra);
void reg_new_channel_func(new_channel_func_t handler, void *extra);
typedef int (*join_func_t) (struct modeNode *mNode, void *extra);
void reg_join_func_pos(join_func_t handler, void *extra, int pos);
void reg_join_func(join_func_t handler, void *extra);
typedef void (*del_channel_func_t) (struct chanNode *chan, void *extra);
void reg_del_channel_func(del_channel_func_t handler, void *extra);

struct chanNode* AddChannel(const char *name, time_t time_, const char *modes, char *banlist, char *exemptlist);
void LockChannel(struct chanNode *channel);
void UnlockChannel(struct chanNode *channel);

struct modeNode* AddChannelUser(struct userNode* user, struct chanNode* channel);

typedef void (*part_func_t) (struct modeNode *mn, const char *reason, void *extra);
void reg_part_func(part_func_t handler, void *extra);
void unreg_part_func(part_func_t handler, void *extra);
void DelChannelUser(struct userNode* user, struct chanNode* channel, const char *reason, int deleting);
void KickChannelUser(struct userNode* target, struct chanNode* channel, struct userNode *kicker, const char *why);

typedef void (*kick_func_t) (struct userNode *kicker, struct userNode *user, struct chanNode *chan, void *extra);
void reg_kick_func(kick_func_t handler, void *extra);
void ChannelUserKicked(struct userNode* kicker, struct userNode* victim, struct chanNode* channel);

int ChannelBanExists(struct chanNode *channel, const char *ban);
int ChannelExemptExists(struct chanNode *channel, const char *exempt);

typedef int (*topic_func_t)(struct userNode *who, struct chanNode *chan, const char *old_topic, void *extra);
void reg_topic_func(topic_func_t handler, void *extra);
void SetChannelTopic(struct chanNode *channel, struct userNode *service, struct userNode *user, const char *topic, int announce);
struct userNode *IsInChannel(struct chanNode *channel, struct userNode *user);

void init_structs(void);

#endif
