/* mod-memoserv.c - MemoServ module for srvx
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

/*
 * /msg opserv bind nickserv * *memoserv.*
 *
 * If you want a dedicated MemoServ bot, make sure the service control
 * commands are bound to OpServ:
 * /msg opserv bind opserv service *modcmd.joiner
 * /msg opserv bind opserv service\ add *modcmd.service\ add
 * /msg opserv bind opserv service\ rename *modcmd.service\ rename
 * /msg opserv bind opserv service\ trigger *modcmd.service\ trigger
 * /msg opserv bind opserv service\ remove *modcmd.service\ remove
 * Add the bot:
 * /msg opserv service add MemoServ User-to-user Memorandum Service
 * /msg opserv bind memoserv help *modcmd.help
 * Restart srvx with the updated conf file (as above, butwith "bot"
 * "MemoServ"), and bind the commands to it:
 * /msg opserv bind memoserv * *memoserv.*
 * /msg opserv bind memoserv set *memoserv.set
 */

#include "chanserv.h"
#include "conf.h"
#include "modcmd.h"
#include "nickserv.h"
#include "opserv.h"
#include "saxdb.h"
#include "mail.h"
#include "timeq.h"

#define KEY_MAIN_ACCOUNTS "accounts"
#define KEY_FLAGS "flags"
#define KEY_LIMIT "limit"

#define KEY_MAIN_HISTORY "history"
#define KEY_MAIN_MEMOS "memos"
#define KEY_SENT "sent"
#define KEY_RECIPIENT "to"
#define KEY_FROM "from"
#define KEY_MESSAGE "msg"
#define KEY_READ "read"
#define KEY_RECIEPT "reciept"
#define KEY_ID "id"


static const struct message_entry msgtab[] = {
    { "MSMSG_CANNOT_SEND", "You cannot send to account $b%s$b." },
    { "MSMSG_UNKNOWN_SEND_FLAG", "Unreccognised send flag '%c', message not sent." },
    { "MSMSG_MEMO_SENT", "Message sent to $b%s$b (ID# %d)." },
    { "MSMSG_NO_MESSAGES", "You have no messages." },
    { "MSMSG_MEMOS_FOUND", "Found $b%d$b matches." },
    { "MSMSG_HOWTO_READ", "Use READ <ID> to read a message." },
    { "MSMSG_CLEAN_INBOX", "You have $b%d$b or more messages, please clean out your inbox.\nUse READ <ID> to read a message." },
    { "MSMSG_LIST_HEAD",      "$bID$b   $bFrom$b       $bTime Sent$b" },
    { "MSMSG_LIST_FORMAT",    "%-2u     %s $b%s$b          %s" },
    { "MSMSG_HISTORY_HEADER", "$bID$b   $bTo$b          $bTime Sent$b" },
    { "MSMSG_HISTORY_FORMAT", "%-2u     %s              %s" },
    { "MSMSG_MEMO_HEAD", "Memo %u From $b%s$b, received on %s:" },
    { "MSMSG_MEMO_RECIEPT", "$bRead Reciept$b requested, %s." },
    { "MSMSG_BAD_MESSAGE_ID", "$b%s$b is not a valid message ID (it should be a number between 0 and %u)." },
    { "MSMSG_NO_SUCH_MEMO", "You have no memo with that ID." },
    { "MSMSG_MEMO_DELETED", "Memo $b%d$b deleted." },
    { "MSMSG_MEMO_CANCEL_NUMBER", "You must specify a number id" },
    { "MSMSG_MEMO_DONT_OWN", "You did not send memo# %d" },
    { "MSMSG_MEMO_READ", "Memo# %d has already been read, you cannot cancel it." },
    { "MSMSG_MEMO_CANT_LOCATE", "Could not locate memo# %d" },
    { "MSMSG_EXPIRY_OFF", "I am currently not expiring messages. (turned off)" },
    { "MSMSG_EXPIRY", "Messages will be expired when they are %s old (%d seconds)." },
    { "MSMSG_MESSAGES_EXPIRED", "$b%lu$b message(s) expired." },
    { "MSMSG_MEMOS_INBOX", "You have $b%d$b new message(s) in your inbox and %d old messages.  Use LIST to list them." },
    { "MSMSG_NEW_MESSAGE", "You have a new message from $b%s$b. Use LIST to see your messages." },
    { "MSMSG_FULL_INBOX",  "$b%s$b cannot recieve anymore memos as their inbox is full" },
    { "MSMSG_DELETED_ALL", "Deleted all of your messages." },
    { "MSMSG_USE_CONFIRM", "Please use DELETE * $bCONFIRM$b to delete $uall$u of your messages." },

    { "MSMSG_STATUS_HIST_TOTAL",   "I have $b%u$b history entries in my database." },
    { "MSMSG_STATUS_TOTAL",   "I have $b%u$b memos in my database." },
    { "MSMSG_STATUS_EXPIRED", "$b%ld$b memos expired during the time I am awake." },
    { "MSMSG_STATUS_SENT",    "$b%ld$b memos have been sent." },

    { "MSMSG_INVALID_OPTION",  "$b%s$b is not a valid option." },
    { "MSMSG_INVALID_BINARY",  "$b%s$b is an invalid binary value." },
    { "MSMSG_SET_AUTHNOTIFY",      "$bAuthNotify$b:       %s" },
    { "MSMSG_SET_NEWNOTIFY",       "$bNewNotify$b:        %s" },
    { "MSMSG_SET_PRIVMSG",         "$bPrivmsg$b:          %s" },
    { "MSMSG_SET_PRIVATE",         "$bPrivate$b:          %s" },
    { "MSMSG_SET_IGNORERECIEPTS",  "$bIgnoreReciepts$b:   %s" },
    { "MSMSG_SET_SENDRECIEPTS",    "$bSendReciepts$b:     %s" },
    { "MSMSG_SET_LIMIT",           "$bLimit$b:            %d" },
    { "MSMSG_SET_OPTIONS",         "$bMessaging Options$b" },
    { "MSMSG_SET_OPTIONS_END", "-------------End of Options-------------" },

    { "MSMSG_LIST_END",        "--------------End of Memos--------------" },
    { "MSMSG_BAR",             "----------------------------------------"},

    { "MSEMAIL_NEWMEMO_SUBJECT", "New %s %s message from %s" },
    { "MSEMAIL_NEWMEMO_BODY", "This email has been sent to let you know that %s has sent you a message via %s.\n\n  The message is: %s.\n\nTo delete this message just type in /msg %s delete %d when on %s next." },

    { "MSMSG_DEFCON_NO_NEW_MEMOS", "You cannot send new memos at this time, please try again soon." },

    { NULL, NULL }
};

struct memo {
    struct memo_account *recipient;
    struct memo_account *sender;
    char *message;
    time_t sent;
    unsigned long id;
    unsigned int is_read : 1;
    unsigned int reciept : 1;
};

struct history {
    struct memo_account *recipient;
    struct memo_account *sender;
    time_t sent;
    unsigned long id;
};

struct userNode *memoserv;

#define MEMOSERV_FUNC(NAME)         MODCMD_FUNC(NAME)
#define MEMOSERV_SYNTAX()           svccmd_send_help_brief(user, memoserv, cmd)
#define MEMOSERV_MIN_PARAMS(N)      if(argc < (N)) {            \
                                     reply("MSG_MISSING_PARAMS", argv[0]); \
                                     MEMOSERV_SYNTAX(); \
                                     return 0; }

DECLARE_LIST(memoList, struct memo*);
DEFINE_LIST(memoList, struct memo*)
DECLARE_LIST(historyList, struct history*);
DEFINE_LIST(historyList, struct history*)

/* memo_account.flags fields */
#define MEMO_NOTIFY_NEW      0x00000001
#define MEMO_NOTIFY_LOGIN    0x00000002
#define MEMO_DENY_NONCHANNEL 0x00000004
#define MEMO_IGNORE_RECIEPTS 0x00000008
#define MEMO_ALWAYS_RECIEPTS 0x00000010
#define MEMO_USE_PRIVMSG     0x00000020

struct memo_account {
    struct handle_info *handle;
    unsigned int flags : 6;
    unsigned int limit;
    struct memoList sent;
    struct memoList recvd;
    struct historyList hsent;
    struct historyList hrecvd;
};

static struct {
    struct userNode *bot;
    int message_expiry;
    unsigned int limit;
} memoserv_conf;

#define MEMOSERV_FUNC(NAME) MODCMD_FUNC(NAME)
#define OPTION_FUNC(NAME) int NAME(struct svccmd *cmd, struct userNode *user, struct handle_info *hi, UNUSED_ARG(unsigned int override), unsigned int argc, char *argv[])
typedef OPTION_FUNC(option_func_t);

unsigned long memo_id;

extern struct string_list *autojoin_channels;
const char *memoserv_module_deps[] = { NULL };
static struct module *memoserv_module;
static struct log_type *MS_LOG;
static unsigned long memoCount;
static unsigned long memosSent;
static unsigned long memosExpired;
static struct dict *memos; /* memo_account->handle->handle -> memo_account */
static struct dict *historys;
static dict_t memoserv_opt_dict; /* contains option_func_t* */

static struct memo_account *
memoserv_get_account(struct handle_info *hi)
{
    struct memo_account *ma;
    if (!hi)
        return NULL;
    ma = dict_find(memos, hi->handle, NULL);
    if (ma)
        return ma;
    ma = calloc(1, sizeof(*ma));
    if (!ma)
        return ma;
    ma->handle = hi;
    ma->flags = MEMO_NOTIFY_NEW | MEMO_NOTIFY_LOGIN | MEMO_USE_PRIVMSG;
    ma->limit = memoserv_conf.limit;
    dict_insert(memos, ma->handle->handle, ma);
    dict_insert(historys, ma->handle->handle, ma);
    return ma;
}

static void
delete_memo(struct memo *memo)
{
    memoList_remove(&memo->recipient->recvd, memo);
    memoList_remove(&memo->sender->sent, memo);
    free(memo->message);
    free(memo);
    memoCount--;
}

static void
delete_history(struct history *history)
{
    historyList_remove(&history->recipient->hrecvd, history);
    historyList_remove(&history->sender->hsent, history);
    free(history);
}

static void
delete_memo_account(void *data)
{
    struct memo_account *ma = data;

    while (ma->recvd.used)
        delete_memo(ma->recvd.list[0]);
    while (ma->sent.used)
        delete_memo(ma->sent.list[0]);
    memoList_clean(&ma->recvd);
    memoList_clean(&ma->sent);

    while (ma->hrecvd.used)
        delete_history(ma->hrecvd.list[0]);
    while (ma->hsent.used)
        delete_history(ma->hsent.list[0]);
    historyList_clean(&ma->hrecvd);
    historyList_clean(&ma->hsent);
    free(ma);
}

void
do_expire(void)
{
    dict_iterator_t it;
    for (it = dict_first(memos); it; it = iter_next(it)) {
        struct memo_account *account = iter_data(it);
        unsigned int ii;
        for (ii = 0; ii < account->sent.used; ++ii) {
            struct memo *memo = account->sent.list[ii];
            if ((now - memo->sent) > memoserv_conf.message_expiry) {
                delete_memo(memo);
                memosExpired++;
                ii--;
            }
        }
    }

    for (it = dict_first(historys); it; it = iter_next(it)) {
        struct memo_account *account = iter_data(it);
        unsigned int ii;
        for (ii = 0; ii < account->hsent.used; ++ii) {
            struct history *history = account->hsent.list[ii];
            if ((now - history->sent) > memoserv_conf.message_expiry) {
                delete_history(history);
                memosExpired++;
                ii--;
            }
        }
    }
}

static void
expire_memos(UNUSED_ARG(void *data))
{
    if (memoserv_conf.message_expiry) {
        do_expire();
        timeq_add(now + memoserv_conf.message_expiry, expire_memos, NULL);
    }
}

static struct history*
add_history(time_t sent, struct memo_account *recipient, struct memo_account *sender, unsigned long id)
{
    struct history *history;

    history = calloc(1, sizeof(*history));
    if (!history)
        return NULL;

    history->id = id;
    history->recipient = recipient;
    historyList_append(&recipient->hrecvd, history);
    history->sender = sender;
    historyList_append(&sender->hsent, history);
    history->sent = sent;

    return history;
}


static struct memo*
add_memo(time_t sent, struct memo_account *recipient, struct memo_account *sender, char *message, int nfrom_read)
{
    struct memo *memo;
    struct history *history;

    memo = calloc(1, sizeof(*memo));
    if (!memo)
        return NULL;

    if (nfrom_read) {
        memo_id++;
        memo->id = memo_id;
    }

    memo->recipient = recipient;
    memoList_append(&recipient->recvd, memo);
    memo->sender = sender;
    memoList_append(&sender->sent, memo);
    memo->sent = sent;
    memo->message = strdup(message);
    memosSent++;
    memoCount++;

    if (nfrom_read)
        history = add_history(sent, recipient, sender, memo->id);

    return memo;
}

static int
memoserv_can_send(struct userNode *bot, struct userNode *user, struct memo_account *acct)
{
    extern struct userData *_GetChannelUser(struct chanData *channel, struct handle_info *handle, int override, int allow_suspended);
    struct userData *dest;
    unsigned int i = 0, match = 0;

    if (!user->handle_info)
        return 0;

    /* Sanity checks here because if the user doesnt have a limit set
       the limit comes out at like 21233242 if you try and use it. */
    if (acct->limit > memoserv_conf.limit)
          acct->limit = memoserv_conf.limit;

    if (acct->recvd.used > acct->limit) {
        send_message(user, bot, "MSMSG_FULL_INBOX", acct->handle->handle);
        send_message(user, bot, "MSMSG_CANNOT_SEND", acct->handle->handle);
        return 0;
    }

    if (acct->handle->ignores->used) {
        for (i=0; i < acct->handle->ignores->used; i++) {
            if (user_matches_glob(user, acct->handle->ignores->list[i], MATCH_USENICK, 0)) {
                match = 1;
                break;
            }
        }

        if (match) {
            send_message(user, bot, "MSMSG_CANNOT_SEND", acct->handle->handle);
            return 0;
        }
    }

    if (!(acct->flags & MEMO_DENY_NONCHANNEL))
        return 1;

    for (dest = acct->handle->channels; dest; dest = dest->u_next)
        if (_GetChannelUser(dest->channel, user->handle_info, 1, 0))
            return 1;

    send_message(user, bot, "MSMSG_CANNOT_SEND", acct->handle->handle);
    return 0;
}

static struct memo *find_memo(struct userNode *user, struct svccmd *cmd, struct memo_account *ma, const char *msgid, unsigned int *id)
{
    unsigned int memoid;
    if (!isdigit(msgid[0])) {
        if (ma->recvd.used)
            reply("MSMSG_BAD_MESSAGE_ID", msgid, ma->recvd.used - 1);
        else
            reply("MSMSG_NO_MESSAGES");
        return NULL;
    }
    memoid = atoi(msgid);
    if (memoid >= ma->recvd.used) {
        reply("MSMSG_NO_SUCH_MEMO");
        return NULL;
    }
    return ma->recvd.list[*id = memoid];
}

static MODCMD_FUNC(cmd_send)
{
    char *message;
    int reciept = 0, inc = 2, email = 0;
    struct handle_info *hi;
    struct memo_account *ma, *sender;
    struct memo *memo;
    char subject[128], body[4096];
    char *estr;
    const char *netname, *fmt;

    MEMOSERV_MIN_PARAMS(3);

    if (checkDefCon(DEFCON_NO_NEW_MEMOS) && !IsOper(user)) {
        reply("MSMSG_DEFCON_NO_NEW_MEMOS");
        return 0;
    }

    if (!(hi = modcmd_get_handle_info(user, argv[1])))
        return 0;

    if (!(sender = memoserv_get_account(user->handle_info))
        || !(ma = memoserv_get_account(hi))) {
        reply("MSG_INTERNAL_FAILURE");
        return 0;
    }

    if (!(memoserv_can_send(cmd->parent->bot, user, ma)))
        return 0;

    inc = 2; /* Start of message on 3rd ([2]) word */
    if(argv[2][0] == '-' && argv[2][1] != '-') { /* first word is flags ('-r')*/
        char *flags = argv[2];
        inc++; /* Start of message is now 1 word later */
        for(flags++;*flags;flags++) {
            switch (*flags) {
                case 'r':
                    reciept = 1;
                break;

            default:
                /* Unknown mode. Give an error */
                reply("MSMSG_UNKNOWN_SEND_FLAG", *flags);
                return 0;
            }
        }
    }
    else
        inc = 2; /* Start of message is word 2 */

    message = unsplit_string(argv + inc, argc - inc, NULL);
    memo = add_memo(now, ma, sender, message, 1);
    if ((reciept == 1) || (ma->flags & MEMO_ALWAYS_RECIEPTS))
        memo->reciept = 1;

    if (ma->flags & MEMO_NOTIFY_NEW) {
        struct userNode *other;

        for (other = ma->handle->users; other; other = other->next_authed)
            send_message_type((ma->flags & MEMO_USE_PRIVMSG)? MSG_TYPE_PRIVMSG : MSG_TYPE_NOTICE, other, memoserv ? memoserv : cmd->parent->bot, "MSMSG_NEW_MESSAGE", user->nick);
    }

    estr = conf_get_data("services/nickserv/email_enabled", RECDB_QSTRING);
    netname = conf_get_data("server/network", RECDB_QSTRING);
    email = atoi(estr);
    if (email && (ma->flags & MEMO_NOTIFY_NEW)) {
        fmt = handle_find_message(hi, "MSEMAIL_NEWMEMO_SUBJECT");
        snprintf(subject, sizeof(subject), fmt, netname, memoserv->nick, user->nick);

        fmt = handle_find_message(hi, "MSEMAIL_NEWMEMO_BODY");
        snprintf(body, sizeof(body), fmt, user->nick, memoserv->nick, message, memoserv->nick, memo_id, netname);

        mail_send(memoserv, hi, subject, body, 0);
    }

    reply("MSMSG_MEMO_SENT", ma->handle->handle, memo_id);
    return 1;
}

static MODCMD_FUNC(cmd_list)
{
    struct memo_account *ma;
    struct memo *memo;
    unsigned int ii;
    char posted[24];
    struct tm tm;

    if (!(ma = memoserv_get_account(user->handle_info)))
        return 0;

    reply("MSMSG_LIST_HEAD");

    if(user->handle_info && user->handle_info->userlist_style != HI_STYLE_CLEAN)
        reply("MSMSG_BAR");

    for (ii = 0; (ii < ma->recvd.used) && (ii < 15); ++ii) {
        memo = ma->recvd.list[ii];
        localtime_r(&memo->sent, &tm);
        strftime(posted, sizeof(posted), "%I:%M %p, %m/%d/%Y", &tm);
        reply("MSMSG_LIST_FORMAT", ii, memo->sender->handle->handle, memo->reciept ? "(r)" : "", posted);
    }
    if (ii == 0)
        reply("MSG_NONE");
    else if (ii == 15)
        reply("MSMSG_CLEAN_INBOX", ii);
    else {
        reply("MSMSG_MEMOS_FOUND", ii);
        reply("MSMSG_HOWTO_READ");
    }

    reply("MSMSG_LIST_END");

    return 1;
}

static MODCMD_FUNC(cmd_history)
{
    struct memo_account *ma;
    struct history *history;
    dict_iterator_t it;
    unsigned int ii = 0;
    unsigned int cc = 0;
    char posted[24];
    struct tm tm;

    if (!(ma = memoserv_get_account(user->handle_info)))
        return 0;

    reply("MSMSG_HISTORY_HEADER");

    if(user->handle_info && user->handle_info->userlist_style != HI_STYLE_CLEAN)
        reply("MSMSG_BAR");

    for (it = dict_first(historys); it; it = iter_next(it)) {
        ma = iter_data(it);
        for (ii = 0; ii < ma->hrecvd.used; ++ii) {
            history = ma->hrecvd.list[ii];
            if (!strcasecmp(history->sender->handle->handle, user->handle_info->handle)) {
                cc++;
                localtime_r(&history->sent, &tm);
                strftime(posted, sizeof(posted), "%I:%M %p, %m/%d/%Y", &tm);
                reply("MSMSG_HISTORY_FORMAT", history->id, history->recipient->handle->handle, posted);
            }
        }
    }

    if (cc == 0)
        reply("MSG_NONE");
    else
        reply("MSMSG_MEMOS_FOUND", cc);

    reply("MSMSG_LIST_END");

    return 1;
}

static MODCMD_FUNC(cmd_read)
{
    struct memo_account *ma;
    unsigned int memoid;
    int rignore = 0, brk = 0, s = 0;
    struct memo *memo;
    struct memo *memob;
    char posted[24];
    struct tm tm;

    if (argc > 2) {
        char *argtwo = argv[2];
        while (*argtwo) {
            switch (*argtwo) {
                case '-':
                    if (s != 0)
                        brk = 1;
                    break;

                case 'i':
                    if (s > 0)
                        rignore = 1;
                    break;

                default: break;
            }

            if (brk == 1)
                break;
            else {
                s++;
                argtwo++;
            }
        }
    }

    if (!(ma = memoserv_get_account(user->handle_info)))
        return 0;
    
    if (!(memo = find_memo(user, cmd, ma, argv[1], &memoid)))
        return 0;

    localtime_r(&memo->sent, &tm);
    strftime(posted, sizeof(posted), "%I:%M %p, %m/%d/%Y", &tm);

    reply("MSMSG_MEMO_HEAD", memoid, memo->sender->handle->handle, posted);
    send_message_type(4, user, cmd->parent->bot, "%s", memo->message);
    memo->is_read = 1;
    memob = memo;

    if (ma->flags & MEMO_IGNORE_RECIEPTS)
        rignore = 1;

    if (memo->reciept == 1) {
        memo->reciept = 0;
        reply("MSMSG_MEMO_RECIEPT", rignore ? "ignoring" : "sending");
        if (rignore == 0) {
	    struct memo_account *ma;
	    struct memo_account *sender;
            char content[MAXLEN];

            ma = memoserv_get_account(user->handle_info);
            sender = memoserv_get_account(memo->sender->handle);

            sprintf(content, "%s has read your memo dated %s.", ma->handle->handle, posted);

            memo = add_memo(now, sender, ma, content, 1);
            reply("MSMSG_MEMO_SENT", memob->sender->handle->handle, memo_id);

            if (sender->flags & MEMO_NOTIFY_NEW) {
                struct userNode *other;

                for (other = sender->handle->users; other; other = other->next_authed)
                    send_message_type((ma->flags & MEMO_USE_PRIVMSG)? MSG_TYPE_PRIVMSG : MSG_TYPE_NOTICE, other, cmd->parent->bot, "MSMSG_NEW_MESSAGE", ma->handle->handle);
            }


        }
    }
    return 1;
}

static MODCMD_FUNC(cmd_delete)
{
    struct memo_account *ma;
    struct memo *memo;
    unsigned int memoid;

    MEMOSERV_MIN_PARAMS(2);

    if (!(ma = memoserv_get_account(user->handle_info)))
        return 0;
    if (!irccasecmp(argv[1], "*") || !irccasecmp(argv[1], "all")) {
        if ((argc < 3) || irccasecmp(argv[2], "confirm")) {
            reply("MSMSG_USE_CONFIRM");
            return 0;
        }
        while (ma->recvd.used)
            delete_memo(ma->recvd.list[0]);
        reply("MSMSG_DELETED_ALL");
        return 1;
    }

    if (!(memo = find_memo(user, cmd, ma, argv[1], &memoid)))
        return 0;
    delete_memo(memo);
    reply("MSMSG_MEMO_DELETED", memoid);
    return 1;
}

static MODCMD_FUNC(cmd_cancel)
{
    unsigned long id;
    unsigned int ii;
    dict_iterator_t it;
    struct memo *memo;
    struct memo_account *ma;

    MEMOSERV_MIN_PARAMS(2);

    if (isdigit(argv[1][0])) {
        id = strtoul(argv[1], NULL, 0);
    } else {
        reply("MSMSG_MEMO_CANCEL_NUMBER");
        return 0;
    }

    for (it = dict_first(memos); it; it = iter_next(it)) {
        ma = iter_data(it);
        for (ii = 0; ii < ma->recvd.used; ++ii) {
            memo = ma->recvd.list[ii];

            if (id == memo->id) {
                if (!strcasecmp(memo->sender->handle->handle, user->handle_info->handle)) {
                    if (memo->is_read) {
                        reply("MSMSG_MEMO_READ", id);
                        return 0;
                    } else {
                        delete_memo(memo);
                        reply("MSMSG_MEMO_DELETED", id);
                        return 1;
                    }
                } else {
                    reply("MSMSG_MEMO_DONT_OWN", id);
                    return 0;
                }
            }
        }
    }

    reply("MSMSG_MEMO_CANT_LOCATE", id);
    return 0;
}

static MODCMD_FUNC(cmd_expire)
{
    unsigned long old_expired = memosExpired;
    do_expire();
    reply("MSMSG_MESSAGES_EXPIRED", memosExpired - old_expired);
    return 1;
}

static MODCMD_FUNC(cmd_expiry)
{
    char interval[INTERVALLEN];

    if (!memoserv_conf.message_expiry) {
        reply("MSMSG_EXPIRY_OFF");
        return 1;
    }

    intervalString(interval, memoserv_conf.message_expiry, user->handle_info);
    reply("MSMSG_EXPIRY", interval, memoserv_conf.message_expiry);
    return 1;
}


static void
set_list(struct svccmd *cmd, struct userNode *user, struct handle_info *hi, int override)
{
    option_func_t *opt;
    unsigned int i;
    char *set_display[] = {"AUTHNOTIFY", "NEWNOTIFY", "PRIVMSG", "PRIVATE", "LIMIT",
                           "IGNORERECIEPTS", "SENDRECIEPTS"};

    reply("MSMSG_SET_OPTIONS");
    reply("MSMSG_BAR");

    /* Do this so options are presented in a consistent order. */
    for (i = 0; i < ArrayLength(set_display); ++i)
        if ((opt = dict_find(memoserv_opt_dict, set_display[i], NULL)))
            opt(cmd, user, hi, override, 0, NULL);
    reply("MSMSG_SET_OPTIONS_END");
}

static MODCMD_FUNC(cmd_set)
{
    struct handle_info *hi;
    option_func_t *opt;

    hi = user->handle_info;
    if (argc < 2) {
        set_list(cmd, user, hi, 0);
        return 1;
    }

    if (!(opt = dict_find(memoserv_opt_dict, argv[1], NULL))) {
        reply("MSMSG_INVALID_OPTION", argv[1]);
        return 0;
    }

    return opt(cmd, user, hi, 0, argc-1, argv+1);
}

static MODCMD_FUNC(cmd_oset)
{
    struct handle_info *hi;
    option_func_t *opt;

    MEMOSERV_MIN_PARAMS(2);

    if (!(hi = get_victim_oper(user, argv[1])))
        return 0;

    if (argc < 3) {
        set_list(cmd, user, hi, 0);
        return 1;
    }

    if (!(opt = dict_find(memoserv_opt_dict, argv[2], NULL))) {
        reply("MSMSG_INVALID_OPTION", argv[2]);
        return 0;
    }

    return opt(cmd, user, hi, 1, argc-2, argv+2);
}

static OPTION_FUNC(opt_newnotify)
{
    struct memo_account *ma;
    char *choice;

    if (!(ma = memoserv_get_account(hi)))
        return 0;
    if (argc > 1) {
        choice = argv[1];
        if (enabled_string(choice)) {
            ma->flags |= MEMO_NOTIFY_NEW;
        } else if (disabled_string(choice)) {
            ma->flags &= ~MEMO_NOTIFY_NEW;
        } else {
            reply("MSMSG_INVALID_BINARY", choice);
            return 0;
        }
    }

    choice = (ma->flags & MEMO_NOTIFY_NEW) ? "on" : "off";
    reply("MSMSG_SET_NEWNOTIFY", choice);
    return 1;
}

static OPTION_FUNC(opt_privmsg)
{
    struct memo_account *ma;
    char *choice;

    if (!(ma = memoserv_get_account(hi)))
        return 0;
    if (argc > 1) {
        choice = argv[1];
        if (enabled_string(choice)) {
            ma->flags |= MEMO_USE_PRIVMSG;
        } else if (disabled_string(choice)) {
            ma->flags &= ~MEMO_USE_PRIVMSG;
        } else {
            reply("MSMSG_INVALID_BINARY", choice);
            return 0;
        }
    }
    choice = (ma->flags & MEMO_USE_PRIVMSG) ? "on" : "off";
    reply("MSMSG_SET_PRIVMSG", choice);
    return 1;
}

static OPTION_FUNC(opt_authnotify)
{
    struct memo_account *ma;
    char *choice;

    if (!(ma = memoserv_get_account(hi)))
        return 0;
    if (argc > 1) {
        choice = argv[1];
        if (enabled_string(choice)) {
            ma->flags |= MEMO_NOTIFY_LOGIN;
        } else if (disabled_string(choice)) {
            ma->flags &= ~MEMO_NOTIFY_LOGIN;
        } else {
            reply("MSMSG_INVALID_BINARY", choice);
            return 0;
        }
    }

    choice = (ma->flags & MEMO_NOTIFY_LOGIN) ? "on" : "off";
    reply("MSMSG_SET_AUTHNOTIFY", choice);
    return 1;
}

static OPTION_FUNC(opt_ignorereciepts)
{
    struct memo_account *ma;
    char *choice;

    if (!(ma = memoserv_get_account(hi)))
        return 0;
    if (argc > 1) {
        choice = argv[1];
        if (enabled_string(choice)) {
            ma->flags |= MEMO_IGNORE_RECIEPTS;
        } else if (disabled_string(choice)) {
            ma->flags &= ~MEMO_IGNORE_RECIEPTS;
        } else {
            reply("MSMSG_INVALID_BINARY", choice);
            return 0;
        }
    }

    choice = (ma->flags & MEMO_IGNORE_RECIEPTS) ? "on" : "off";
    reply("MSMSG_SET_IGNORERECIEPTS", choice);
    return 1;
}

static OPTION_FUNC(opt_sendreciepts)
{ 
    struct memo_account *ma;
    char *choice;

    if (!(ma = memoserv_get_account(hi)))
        return 0;
    if (argc > 1) {
        choice = argv[1];
        if (enabled_string(choice)) {
            ma->flags |= MEMO_ALWAYS_RECIEPTS;
        } else if (disabled_string(choice)) {
            ma->flags &= ~MEMO_ALWAYS_RECIEPTS;
        } else {
            reply("MSMSG_INVALID_BINARY", choice);
            return 0;
        }
    }

    choice = (ma->flags & MEMO_ALWAYS_RECIEPTS) ? "on" : "off";
    reply("MSMSG_SET_SENDRECIEPTS", choice);
    return 1;
}

static OPTION_FUNC(opt_private)
{
    struct memo_account *ma;
    char *choice;

    if (!(ma = memoserv_get_account(hi)))
        return 0;
    if (argc > 1) {
        choice = argv[1];
        if (enabled_string(choice)) {
            ma->flags |= MEMO_DENY_NONCHANNEL;
        } else if (disabled_string(choice)) {
            ma->flags &= ~MEMO_DENY_NONCHANNEL;
        } else {
            reply("MSMSG_INVALID_BINARY", choice);
            return 0;
        }
    }

    choice = (ma->flags & MEMO_DENY_NONCHANNEL) ? "on" : "off";
    reply("MSMSG_SET_PRIVATE", choice);
    return 1;
}

static OPTION_FUNC(opt_limit)
{
    struct memo_account *ma;
    unsigned int choice;

    if (!(ma = memoserv_get_account(hi)))
        return 0;
    if (argc > 1) {
        choice = atoi(argv[1]);
        if (choice > memoserv_conf.limit)
          choice = memoserv_conf.limit;

        ma->limit = choice;
    }

    reply("MSMSG_SET_LIMIT", ma->limit);
    return 1;
}

static MODCMD_FUNC(cmd_status)
{
    struct memo_account *ma;
    dict_iterator_t it;
    int mc = 0, hc = 0;
    unsigned int ii;

    for (it = dict_first(memos); it; it = iter_next(it)) {
        ma = iter_data(it);
        for (ii = 0; ii < ma->recvd.used; ++ii)
            mc++;
    }

    for (it = dict_first(historys); it; it = iter_next(it)) {
        ma = iter_data(it);
        for (ii = 0; ii < ma->hrecvd.used; ++ii)
            hc++;
    }

    reply("MSMSG_STATUS_HIST_TOTAL", hc);
    reply("MSMSG_STATUS_TOTAL", memoCount);
    reply("MSMSG_STATUS_EXPIRED", memosExpired);
    reply("MSMSG_STATUS_SENT", memosSent);
    return 1;
}

static void
memoserv_conf_read(void)
{
    dict_t conf_node;
    const char *str;

    str = "modules/memoserv";
    if (!(conf_node = conf_get_data(str, RECDB_OBJECT))) {
        log_module(MS_LOG, LOG_ERROR, "config node `%s' is missing or has wrong type.", str);
        return;
    }

    str = database_get_data(conf_node, "limit", RECDB_QSTRING);
    memoserv_conf.limit = str ? atoi(str) : 50;

    str = database_get_data(conf_node, "message_expiry", RECDB_QSTRING);
    memoserv_conf.message_expiry = str ? ParseInterval(str) : 60*24*30;
}

static int
memoserv_user_read(const char *key, struct record_data *hir)
{
    char *str;
    struct memo_account *ma;
    struct handle_info *hi;

    if (!(hi = get_handle_info(key)))
        return 0;

    ma = dict_find(memos, hi->handle, NULL);
    if (ma)
        return 0;


    ma = calloc(1, sizeof(*ma));
    if (!ma)
        return 0;

    ma->handle = hi;

    str = database_get_data(hir->d.object, KEY_FLAGS, RECDB_QSTRING);
    if (!str) {
        log_module(MS_LOG, LOG_ERROR, "Flags not present in memo %s; skipping", key);
        return 0;
    }
    ma->flags = strtoul(str, NULL, 0);

    str = database_get_data(hir->d.object, KEY_LIMIT, RECDB_QSTRING);
    if (!str) {
        log_module(MS_LOG, LOG_ERROR, "Limit not present in memo %s; skipping", key);
        return 0;
    }
    ma->limit = strtoul(str, NULL, 0);

    dict_insert(memos, ma->handle->handle, ma);
    dict_insert(historys, ma->handle->handle, ma);

    return 0;
}

static int
memoserv_memo_read(const char *key, struct record_data *hir)
{
    char *str;
    struct handle_info *sender, *recipient;
    struct memo *memo;
    unsigned long id;
    time_t sent;

    if (hir->type != RECDB_OBJECT) {
        log_module(MS_LOG, LOG_WARNING, "Unexpected rectype %d for %s.", hir->type, key);
        return 0;
    }

    if (!(str = database_get_data(hir->d.object, KEY_SENT, RECDB_QSTRING))) {
        log_module(MS_LOG, LOG_ERROR, "Date sent not present in memo %s; skipping", key);
        return 0;
    }

    sent = atoi(str);

    if (!(str = database_get_data(hir->d.object, KEY_ID, RECDB_QSTRING))) {
        log_module(MS_LOG, LOG_ERROR, "ID sent not present in memo %s; skipping", key);
        return 0;
    }
    id = strtoul(str, NULL, 0);
    if (id > memo_id)
      memo_id = id;

    if (!(str = database_get_data(hir->d.object, KEY_RECIPIENT, RECDB_QSTRING))) {
        log_module(MS_LOG, LOG_ERROR, "Recipient not present in memo %s; skipping", key);
        return 0;
    } else if (!(recipient = get_handle_info(str))) {
        log_module(MS_LOG, LOG_ERROR, "Invalid recipient %s in memo %s; skipping", str, key);
        return 0;
    }

    if (!(str = database_get_data(hir->d.object, KEY_FROM, RECDB_QSTRING))) {
        log_module(MS_LOG, LOG_ERROR, "Sender not present in memo %s; skipping", key);
        return 0;
    } else if (!(sender = get_handle_info(str))) {
        log_module(MS_LOG, LOG_ERROR, "Invalid sender %s in memo %s; skipping", str, key);
        return 0;
    }

    if (!(str = database_get_data(hir->d.object, KEY_MESSAGE, RECDB_QSTRING))) {
        log_module(MS_LOG, LOG_ERROR, "Message not present in memo %s; skipping", key);
        return 0;
    }

    memo = add_memo(sent, memoserv_get_account(recipient), memoserv_get_account(sender), str, 0);
    if ((str = database_get_data(hir->d.object, KEY_READ, RECDB_QSTRING)))
        memo->is_read = 1;

    if ((str = database_get_data(hir->d.object, KEY_RECIEPT, RECDB_QSTRING)))
        memo->reciept = 1;

    memo->id = id;

    return 0;
}

static int
memoserv_history_read(const char *key, struct record_data *hir)
{
    char *str;
    struct handle_info *sender, *recipient;
    struct history *history;
    unsigned long id;
    time_t sent;

    if (hir->type != RECDB_OBJECT) {
        log_module(MS_LOG, LOG_WARNING, "Unexpected rectype %d for %s.", hir->type, key);
        return 0;
    }

    if (!(str = database_get_data(hir->d.object, KEY_SENT, RECDB_QSTRING))) {
        log_module(MS_LOG, LOG_ERROR, "Date sent not present in history %s; skipping", key);
        return 0;
    }

    sent = atoi(str);

    if (!(str = database_get_data(hir->d.object, KEY_ID, RECDB_QSTRING))) {
        log_module(MS_LOG, LOG_ERROR, "ID sent not present in history %s; skipping", key);
        return 0;
    }
    id = strtoul(str, NULL, 0);

    if (!(str = database_get_data(hir->d.object, KEY_RECIPIENT, RECDB_QSTRING))) {
        log_module(MS_LOG, LOG_ERROR, "Recipient not present in history %s; skipping", key);
        return 0;
    } else if (!(recipient = get_handle_info(str))) {
        log_module(MS_LOG, LOG_ERROR, "Invalid recipient %s in history %s; skipping", str, key);
        return 0;
    }

    if (!(str = database_get_data(hir->d.object, KEY_FROM, RECDB_QSTRING))) {
        log_module(MS_LOG, LOG_ERROR, "Sender not present in history %s; skipping", key);
        return 0;
    } else if (!(sender = get_handle_info(str))) {
        log_module(MS_LOG, LOG_ERROR, "Invalid sender %s in history %s; skipping", str, key);
        return 0;
    }

    history = add_history(sent, memoserv_get_account(recipient), memoserv_get_account(sender), id);

    return 0;
}

static int
memoserv_saxdb_read(struct dict *database)
{
    struct dict *section;
    dict_iterator_t it;

    if((section = database_get_data(database, KEY_MAIN_ACCOUNTS, RECDB_OBJECT)))
        for(it = dict_first(section); it; it = iter_next(it))
            memoserv_user_read(iter_key(it), iter_data(it));

    if((section = database_get_data(database, KEY_MAIN_MEMOS, RECDB_OBJECT)))
        for(it = dict_first(section); it; it = iter_next(it))
            memoserv_memo_read(iter_key(it), iter_data(it));

    if((section = database_get_data(database, KEY_MAIN_HISTORY, RECDB_OBJECT)))
        for(it = dict_first(section); it; it = iter_next(it))
            memoserv_history_read(iter_key(it), iter_data(it));

    return 0;
}

static int
memoserv_write_users(struct saxdb_context *ctx, struct memo_account *ma)
{
    saxdb_start_record(ctx, ma->handle->handle, 0);

    saxdb_write_int(ctx, KEY_FLAGS, ma->flags);
    saxdb_write_int(ctx, KEY_LIMIT, ma->limit);

    saxdb_end_record(ctx);
    return 0;
}

static int
memoserv_write_memos(struct saxdb_context *ctx, struct memo *memo)
{
    char str[20];

    memset(str, '\0', sizeof(str));
    saxdb_start_record(ctx, inttobase64(str, memo->id, sizeof(str)-1), 0);

    saxdb_write_int(ctx, KEY_SENT, memo->sent);
    saxdb_write_int(ctx, KEY_ID, memo->id);
    saxdb_write_string(ctx, KEY_RECIPIENT, memo->recipient->handle->handle);
    saxdb_write_string(ctx, KEY_FROM, memo->sender->handle->handle);
    saxdb_write_string(ctx, KEY_MESSAGE, memo->message);

    if (memo->is_read)
        saxdb_write_int(ctx, KEY_READ, 1);

    if (memo->reciept)
        saxdb_write_int(ctx, KEY_RECIEPT, 1);

    saxdb_end_record(ctx);
    return 0;
}

static int
memoserv_write_history(struct saxdb_context *ctx, struct history *history)
{
    char str[20];

    memset(str, '\0', sizeof(str));
    saxdb_start_record(ctx, inttobase64(str, history->id, sizeof(str)-1), 0);

    saxdb_write_int(ctx, KEY_SENT, history->sent);
    saxdb_write_int(ctx, KEY_ID, history->id);
    saxdb_write_string(ctx, KEY_RECIPIENT, history->recipient->handle->handle);
    saxdb_write_string(ctx, KEY_FROM, history->sender->handle->handle);

    saxdb_end_record(ctx);
    return 0;
}

static int
memoserv_saxdb_write(struct saxdb_context *ctx)
{
    dict_iterator_t it;
    struct memo_account *ma;
    struct memo *memo;
    struct history *history;
    unsigned int ii;

    /* Accounts */
    saxdb_start_record(ctx, KEY_MAIN_ACCOUNTS, 1);
    for (it = dict_first(memos); it; it = iter_next(it)) {
        ma = iter_data(it);
        memoserv_write_users(ctx, ma);
    }
    saxdb_end_record(ctx);

    /* Memos */
    saxdb_start_record(ctx, KEY_MAIN_MEMOS, 1);
    for (it = dict_first(memos); it; it = iter_next(it)) {
        ma = iter_data(it);
        for (ii = 0; ii < ma->recvd.used; ++ii) {
            memo = ma->recvd.list[ii];
            memoserv_write_memos(ctx, memo);
        }
    }
    saxdb_end_record(ctx);

    /* History */
    saxdb_start_record(ctx, KEY_MAIN_HISTORY, 1);
    for (it = dict_first(historys); it; it = iter_next(it)) {
        ma = iter_data(it);
        for (ii = 0; ii < ma->hrecvd.used; ++ii) {
            history = ma->hrecvd.list[ii];
            memoserv_write_history(ctx, history);
        }
    }
    saxdb_end_record(ctx);

    return 0;
}

static void
memoserv_cleanup(void)
{
    dict_delete(memos);
    dict_delete(historys);
}

static void
memoserv_check_messages(struct userNode *user, UNUSED_ARG(struct handle_info *old_handle))
{
    unsigned int ii, unseen;
    struct memo_account *ma;
    struct memo *memo;

    if (!user->uplink->burst) {
        if (!(ma = memoserv_get_account(user->handle_info))
            || !(ma->flags & MEMO_NOTIFY_LOGIN))
            return;
        for (ii = unseen = 0; ii < ma->recvd.used; ++ii) {
            memo = ma->recvd.list[ii];
            if (!memo->is_read)
                unseen++;
        }
        if (ma->recvd.used && memoserv)
            if(unseen) send_message_type((ma->flags & MEMO_USE_PRIVMSG)? 1 : 0, user, memoserv, "MSMSG_MEMOS_INBOX", unseen, ma->recvd.used - unseen);
    }
}

static void
memoserv_rename_account(struct handle_info *hi, const char *old_handle, UNUSED_ARG(void *extra))
{
    struct memo_account *ma;
    if (!(ma = dict_find(memos, old_handle, NULL)))
        return;
    dict_remove2(memos, old_handle, 1);
    dict_insert(memos, hi->handle, ma);

    dict_remove2(historys, old_handle, 1);
    dict_insert(historys, hi->handle, ma);
}

static void
memoserv_unreg_account(UNUSED_ARG(struct userNode *user), struct handle_info *handle)
{
    dict_remove(memos, handle->handle);
    dict_remove(historys, handle->handle);
}

int
memoserv_init(void)
{
    MS_LOG = log_register_type("MemoServ", "file:memoserv.log");
    memos = dict_new();
    historys = dict_new();
    dict_set_free_data(memos, delete_memo_account);
    reg_auth_func(memoserv_check_messages);
    reg_handle_rename_func(memoserv_rename_account, NULL);
    reg_unreg_func(memoserv_unreg_account);
    conf_register_reload(memoserv_conf_read);
    reg_exit_func(memoserv_cleanup);
    saxdb_register("MemoServ", memoserv_saxdb_read, memoserv_saxdb_write);

    memoserv_module = module_register("MemoServ", MS_LOG, "mod-memoserv.help", NULL);
    modcmd_register(memoserv_module, "send",    cmd_send,    3, MODCMD_REQUIRE_AUTHED, NULL);
    modcmd_register(memoserv_module, "list",    cmd_list,    1, MODCMD_REQUIRE_AUTHED, NULL);
    modcmd_register(memoserv_module, "read",    cmd_read,    2, MODCMD_REQUIRE_AUTHED, NULL);
    modcmd_register(memoserv_module, "delete",  cmd_delete,  2, MODCMD_REQUIRE_AUTHED, NULL);
    modcmd_register(memoserv_module, "cancel",  cmd_cancel,  2, MODCMD_REQUIRE_AUTHED, NULL);
    modcmd_register(memoserv_module, "history", cmd_history, 1, MODCMD_REQUIRE_AUTHED, NULL);
    modcmd_register(memoserv_module, "expire",  cmd_expire,  1, MODCMD_REQUIRE_AUTHED, "flags", "+oper", NULL);
    modcmd_register(memoserv_module, "expiry",  cmd_expiry,  1,                        0, NULL);
    modcmd_register(memoserv_module, "status",  cmd_status,  1,                        0, NULL);
    modcmd_register(memoserv_module, "set",     cmd_set,     1, MODCMD_REQUIRE_AUTHED, NULL);
    modcmd_register(memoserv_module, "oset",    cmd_oset,    1, MODCMD_REQUIRE_AUTHED, "flags", "+helping", NULL);

    memoserv_opt_dict = dict_new();
    dict_insert(memoserv_opt_dict, "AUTHNOTIFY", opt_authnotify);
    dict_insert(memoserv_opt_dict, "NEWNOTIFY", opt_newnotify);
    dict_insert(memoserv_opt_dict, "PRIVMSG", opt_privmsg);
    dict_insert(memoserv_opt_dict, "PRIVATE", opt_private);
    dict_insert(memoserv_opt_dict, "IGNORERECIEPTS", opt_ignorereciepts);
    dict_insert(memoserv_opt_dict, "SENDRECIEPTS", opt_sendreciepts);
    dict_insert(memoserv_opt_dict, "LIMIT", opt_limit);

    message_register_table(msgtab);

    if (memoserv_conf.message_expiry)
        timeq_add(now + memoserv_conf.message_expiry, expire_memos, NULL);

    return 1;
}

int
memoserv_finalize(void) {
    struct chanNode *chan;
    unsigned int i;
    dict_t conf_node;
    const char *str;

    str = "modules/memoserv";
    if (!(conf_node = conf_get_data(str, RECDB_OBJECT))) {
        log_module(MS_LOG, LOG_ERROR, "config node `%s' is missing or has wrong type.", str);
        return 0;
    }

    str = database_get_data(conf_node, "bot", RECDB_QSTRING);
    if (str) {
        memoserv = memoserv_conf.bot;
        const char *modes = conf_get_data("modules/memoserv/modes", RECDB_QSTRING);
        memoserv = AddLocalUser(str, str, NULL, "User-User Memorandum Services", modes);
    } else {
        log_module(MS_LOG, LOG_ERROR, "database_get_data for memoserv_conf.bot failed!");
        exit(1);
    }

    if (autojoin_channels && memoserv) {
        for (i = 0; i < autojoin_channels->used; i++) {
            chan = AddChannel(autojoin_channels->list[i], now, "+nt", NULL, NULL);
            AddChannelUser(memoserv, chan)->modes |= MODE_CHANOP;
        }
    }

    return 1;
}
