/* x3kc.c - X3's Keycloak backend
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
 *
 * Built only with WITH_KEYCLOAK (configure adds it to MODULE_OBJS).
 */

#include "common.h"
#include "kcid.h"
#include "log.h"
#include "nickserv.h"
#include "x3_kc_adapter.h"
#include "x3kc.h"
#include "x3kc_pure.h"

#include <curl/curl.h>
#include <kc/kc.h>
#include <kc/kc_jwt.h>
#include <kc/kc_keycloak.h>

#include <stdlib.h>
#include <string.h>

extern struct nickserv_config nickserv_conf;

static struct log_type *KC_LOG;

/* kc_init() has run: libcurl's multi handle exists, on the adapter. */
static int kc_running;
/* kc_keycloak_init() has run and kc_keycloak_shutdown() has not since.
 * While it is 0 every seam call is answered X3KC_UNREACHABLE at once and
 * nothing reaches kc. */
static int kc_configured;
/* Counts kc_keycloak_shutdown()s: what was learnt from Keycloak before
 * one (the oper group's id) is not trusted after it. */
static unsigned long kc_gen;

/* What kc_keycloak_init() was last given.  Copies: the strings in
 * nickserv_conf point into the config database, which a rehash replaces
 * before nickserv_conf_read() runs again. */
static char *applied_url;
static char *applied_realm;
static char *applied_client_id;
static char *applied_secret;
static unsigned int applied_timeout;

/* The id of keycloak_oper_group, looked up at its first use after kc was
 * (re)started or the setting changed. */
static char *group_cache_path;
static char *group_cache_id;

/* ------------------------------------------------------------------ */
/* Records                                                            */
/* ------------------------------------------------------------------ */

/* One per seam call that could not be answered at once.  kc's callback
 * data is always a record, never the caller's data, so that:
 *   - the caller is answered exactly once, by kc's answer or by the
 *     deadline, whichever comes first (`answered`);
 *   - kc's answer after the deadline (or after a restart) is dropped, and
 *     the record is freed only then: kc still holds it until it calls back;
 *   - requests in flight are counted (`counted`, `inflight`) for
 *     keycloak_max_pending, until kc's last callback for the record.
 * A queued look-up or delete is a record that has not reached kc yet
 * (`queued`): each waits in its own first-come, first-served queue, and
 * both start within the same share of the slots, look-ups first
 * (x3kc_queue_next()).  Neither has a deadline until it starts (from
 * then on, keycloak_timeout): a netjoin's stamp look-ups each get their
 * full time with Keycloak however long they waited, and an expiry run's
 * deletes may wait as long as it takes, but never in front of a look-up.
 * At exit every record is `dead`: kc's callbacks for it free it and answer
 * no one. */
enum x3kc_kind { KIND_LOGIN, KIND_LOOKUP, KIND_DELETE, KIND_SET_OPER };

enum x3kc_step { STEP_NONE, STEP_GROUP_LOOKUP, STEP_GROUP_CHANGE, STEP_REPR_GET, STEP_UPDATE };

struct x3kc_rec {
    struct x3kc_rec *prev, *next;       /* every record */
    struct x3kc_rec *qprev, *qnext;     /* its queue (queue_of()) */
    enum x3kc_kind kind;
    union {
        x3kc_login_cb login;
        x3kc_user_cb user;
        x3kc_done_cb done;
    } cb;
    void *data;
    void *timer;                        /* the deadline; NULL once spent or cancelled */
    unsigned int answered : 1;
    unsigned int dead : 1;
    unsigned int counted : 1;
    unsigned int queued : 1;
    unsigned int group_done : 1;
    unsigned int arm_at_start : 1;      /* queued look-up: the deadline runs from its start */
    char *account;                      /* queued look-up, login: the name */
    /* set_oper */
    enum x3kc_step step;
    unsigned long gen;
    char uuid[37];
    int in_group;
    unsigned int level;
    char *group_path;                   /* NULL: no group part */
    char *group_id;
    char *field;                        /* NULL: no attribute part */
};

static struct x3kc_rec *rec_head;
static unsigned int inflight;

/* Calls waiting for a slot.  All queue handling is in this file's
 * "queues" functions below (queue_of() to pump()). */
struct rec_queue {
    struct x3kc_rec *head, *tail;
};
static struct rec_queue lookup_queue, delete_queue;

static const char *
kind_name(enum x3kc_kind kind)
{
    switch (kind) {
    case KIND_LOGIN:    return "login";
    case KIND_LOOKUP:   return "look-up";
    case KIND_DELETE:   return "delete";
    case KIND_SET_OPER: return "oper level change";
    }
    return "call";
}

static unsigned long
deadline_ms(void)
{
    /* kc itself takes 0 as 10 s. */
    return nickserv_conf.keycloak_timeout ? nickserv_conf.keycloak_timeout : 10000;
}

/* Every call that does not queue checks the full cap. */
static int
seam_full(void)
{
    return inflight >= nickserv_conf.keycloak_max_pending;
}

/* Queued look-ups and deletes start only while they leave a reserve of
 * slots for the calls that do not queue (x3kc_queue_slots()), so a burst
 * of look-ups or an expiry run's deletes never crowds logins out. */
static int
queue_share_full(void)
{
    return inflight >= x3kc_queue_slots(nickserv_conf.keycloak_max_pending);
}

static struct x3kc_rec *
rec_new(enum x3kc_kind kind, void *data)
{
    struct x3kc_rec *r = calloc(1, sizeof(*r));

    if (!r)
        return NULL;
    r->kind = kind;
    r->data = data;
    r->gen = kc_gen;
    r->next = rec_head;
    if (rec_head)
        rec_head->prev = r;
    rec_head = r;
    return r;
}

/* Only once nothing holds r: not counted (kc has called back for the last
 * time, or never had it), not queued, no deadline armed. */
static void
rec_free(struct x3kc_rec *r)
{
    if (r->prev)
        r->prev->next = r->next;
    else
        rec_head = r->next;
    if (r->next)
        r->next->prev = r->prev;
    free(r->account);
    free(r->group_path);
    free(r->group_id);
    free(r->field);
    free(r);
}

static void
rec_count(struct x3kc_rec *r)
{
    if (!r->counted) {
        r->counted = 1;
        inflight++;
    }
}

static void
rec_uncount(struct x3kc_rec *r)
{
    if (r->counted) {
        r->counted = 0;
        inflight--;
    }
}

static void
rec_disarm(struct x3kc_rec *r)
{
    if (r->timer) {
        x3_kc_get_event_ops()->timer_cancel(r->timer);
        r->timer = NULL;
    }
}

/* ---- queues ---- */

static struct rec_queue *
queue_of(const struct x3kc_rec *r)
{
    return r->kind == KIND_DELETE ? &delete_queue : &lookup_queue;
}

static void
queue_append(struct x3kc_rec *r)
{
    struct rec_queue *q = queue_of(r);

    r->queued = 1;
    r->qnext = NULL;
    r->qprev = q->tail;
    if (q->tail)
        q->tail->qnext = r;
    else
        q->head = r;
    q->tail = r;
}

static void
queue_remove(struct x3kc_rec *r)
{
    struct rec_queue *q = queue_of(r);

    if (!r->queued)
        return;
    if (r->qprev)
        r->qprev->qnext = r->qnext;
    else
        q->head = r->qnext;
    if (r->qnext)
        r->qnext->qprev = r->qprev;
    else
        q->tail = r->qprev;
    r->qprev = r->qnext = NULL;
    r->queued = 0;
}

/* Whether a new look-up (is_delete 0) or delete (1) that may queue must
 * wait rather than start now. */
static int
queue_must_wait(int is_delete)
{
    return x3kc_queue_must_wait(is_delete, lookup_queue.head != NULL, delete_queue.head != NULL,
                                queue_share_full());
}

/* The oldest waiting call of either queue (look-ups first), for draining
 * at a restart or at exit; NULL when both are empty. */
static struct x3kc_rec *
queue_first(void)
{
    return lookup_queue.head ? lookup_queue.head : delete_queue.head;
}

/* Answers r's caller -- unless it was answered already or r is dead --
 * and frees r unless kc (counted) or the queue still holds it.  The
 * strings are the caller's to read during its callback only; they are
 * never r's.  The caller's callback runs last, with r possibly freed, so
 * it may call into the seam again. */
static void
rec_answer(struct x3kc_rec *r, enum x3kc_result res, const char *kcid,
           const char *email, const char *reason)
{
    enum x3kc_kind kind = r->kind;
    x3kc_login_cb login_cb = r->cb.login;
    x3kc_user_cb user_cb = r->cb.user;
    x3kc_done_cb done_cb = r->cb.done;
    void *data = r->data;
    int call = !r->answered && !r->dead;

    r->answered = 1;
    rec_disarm(r);
    if (!r->counted && !r->queued)
        rec_free(r);
    if (!call)
        return;
    switch (kind) {
    case KIND_LOGIN:
        login_cb(res, kcid, email, reason, data);
        break;
    case KIND_LOOKUP:
        user_cb(res, kcid, email, data);
        break;
    case KIND_DELETE:
    case KIND_SET_OPER:
        done_cb(res, data);
        break;
    }
}

static void lookup_start(struct x3kc_rec *r, const char *account);
static void delete_start(struct x3kc_rec *r);

/* Starts queued calls while their share of the slots has room: every
 * queued look-up before any queued delete, each queue in order.  Not
 * re-entered: a call answered while it is being started frees its slot
 * and calls this again, and the loop below picks that slot up. */
static void
pump(void)
{
    static int pumping;
    struct x3kc_rec *r;

    if (pumping)
        return;
    pumping = 1;
    while (kc_configured) {
        switch (x3kc_queue_next(lookup_queue.head != NULL, delete_queue.head != NULL,
                                queue_share_full())) {
        case X3KC_QUEUE_LOOKUP:
            r = lookup_queue.head;
            queue_remove(r);
            lookup_start(r, r->account);
            continue;
        case X3KC_QUEUE_DELETE:
            r = delete_queue.head;
            queue_remove(r);
            delete_start(r);
            continue;
        case X3KC_QUEUE_NONE:
            break;
        }
        break;
    }
    pumping = 0;
}

/* ---- end of queues ---- */

/* r's last request is over (kc called back, or refused to start it):
 * answer the caller and free the slot. */
static void
rec_done(struct x3kc_rec *r, enum x3kc_result res, const char *kcid,
         const char *email, const char *reason)
{
    rec_uncount(r);
    rec_answer(r, res, kcid, email, reason);
    pump();
}

/* First thing in every kc callback.  Returns 1 if r goes on; 0 if its
 * caller was answered already (the deadline, a restart, exit), in which
 * case this was kc's last word on r and r is gone. */
static int
rec_returned(struct x3kc_rec *r)
{
    if (!r->answered)
        return 1;
    rec_uncount(r);
    rec_free(r);
    pump();
    return 0;
}

/* Calls that got no answer from Keycloak are logged quietly: those
 * answered UNREACHABLE at their deadline, and those that failed without an
 * answer (Keycloak refusing connections, no service token, an error
 * status).  A netjoin during an outage can bring hundreds of look-ups.  The
 * first of a run gets its own line (the caller's, at WARNING), then at most
 * one line per QUIET_SUMMARY_SECS with the counts since the last line.
 * quiet_summary_timer is armed while a run is going on (it is the
 * adapter's, so it exists only while kc runs; x3kc_exit() cancels it). */
#define QUIET_SUMMARY_SECS 10
enum quiet_cause { QUIET_DEADLINE, QUIET_FAILED };
static void *quiet_summary_timer;
static unsigned int quiet_count[2];

static void
quiet_summary(UNUSED_ARG(void *arg))
{
    quiet_summary_timer = NULL;         /* spent */
    if (!quiet_count[QUIET_DEADLINE] && !quiet_count[QUIET_FAILED])
        return;                         /* the run is over */
    log_module(KC_LOG, LOG_WARNING, "In the last %us, %u Keycloak call(s) were answered UNREACHABLE at their deadline (%lu ms) and %u failed without an answer or were refused.",
               QUIET_SUMMARY_SECS, quiet_count[QUIET_DEADLINE], deadline_ms(), quiet_count[QUIET_FAILED]);
    quiet_count[QUIET_DEADLINE] = quiet_count[QUIET_FAILED] = 0;
    quiet_summary_timer = x3_kc_get_event_ops()->timer_add(QUIET_SUMMARY_SECS * 1000UL, quiet_summary, NULL);
}

/* Notes a call that got no answer.  1: no run is going on, the caller
 * writes its own line at WARNING (this starts a run); 0: counted for the
 * next summary line. */
static int
quiet_note(enum quiet_cause cause)
{
    if (quiet_summary_timer) {
        quiet_count[cause]++;
        return 0;
    }
    quiet_summary_timer = x3_kc_get_event_ops()->timer_add(QUIET_SUMMARY_SECS * 1000UL, quiet_summary, NULL);
    return 1;
}

static void
deadline_note(struct x3kc_rec *r)
{
    if (quiet_note(QUIET_DEADLINE))
        log_module(KC_LOG, LOG_WARNING, "Keycloak did not answer a %s within %lu ms; further calls without an answer are counted, one line per %us.",
                   kind_name(r->kind), deadline_ms(), QUIET_SUMMARY_SECS);
}

/* A call kc answered with a failure that is not Keycloak's verdict on the
 * user (an outage, no service token, an error status): logged at DEBUG
 * every time, and quietly at WARNING as above. */
static void
failure_note(const char *what, int result)
{
    log_module(KC_LOG, LOG_DEBUG, "Keycloak %s failed (kc result %d).", what, result);
    if (quiet_note(QUIET_FAILED))
        log_module(KC_LOG, LOG_WARNING, "Keycloak %s failed (kc result %d); further calls without an answer are counted, one line per %us.",
                   what, result, QUIET_SUMMARY_SECS);
}

/* The deadline: keycloak_timeout ms after the call, or for a queued
 * look-up or a delete after its request starts (a queued call has none
 * while it waits). */
static void
rec_deadline(void *arg)
{
    struct x3kc_rec *r = arg;

    r->timer = NULL;            /* spent: never cancel it */
    deadline_note(r);
    queue_remove(r);
    rec_answer(r, X3KC_UNREACHABLE, NULL, NULL, NULL);
}

/* Arms r's deadline.  Returns 0, or -1 having answered r (and freed it). */
static int
rec_arm(struct x3kc_rec *r)
{
    r->timer = x3_kc_get_event_ops()->timer_add(deadline_ms(), rec_deadline, r);
    if (r->timer)
        return 0;
    rec_answer(r, X3KC_UNREACHABLE, NULL, NULL, NULL);
    return -1;
}

/* Answers every call in flight X3KC_UNREACHABLE (kc is being restarted or
 * turned off; kc_configured is already 0, so the callers' callbacks cannot
 * reach kc and no record is created or freed by them: the walk below is
 * safe).  Queued look-ups go; records kc holds stay, answered, until kc
 * calls back for them. */
static void
seam_abort_all(void)
{
    struct x3kc_rec *r, *next;
    unsigned int n = 0;

    while ((r = queue_first()) != NULL) {
        queue_remove(r);
        /* A queued delete was never sent: "not sent" (BUSY), not
         * "unconfirmed". */
        rec_answer(r, r->kind == KIND_DELETE ? X3KC_BUSY : X3KC_UNREACHABLE, NULL, NULL, NULL);
        n++;
    }
    for (r = rec_head; r; r = next) {
        next = r->next;
        if (!r->answered) {
            rec_answer(r, X3KC_UNREACHABLE, NULL, NULL, NULL);
            n++;
        }
    }
    if (n)
        log_module(KC_LOG, LOG_INFO, "Answered %u Keycloak call(s) in flight as unreachable.", n);
}

/* An email address from Keycloak: X3KC_EMAIL_MAX bytes at most, no control
 * character or space, an '@', and X3's own rule for an address (tools.c
 * valid_email(), as REGISTER and SET EMAIL apply it).  Else NULL. */
static const char *
seam_email(const char *in, char out[X3KC_EMAIL_MAX + 1])
{
    const char *email = x3kc_clean_email(in, out);

    return email && valid_email(email) ? email : NULL;
}

/* ------------------------------------------------------------------ */
/* Login                                                              */
/* ------------------------------------------------------------------ */

static void
login_cb(int result, const struct kc_access_token *token, const char *reason, void *data)
{
    struct x3kc_rec *r = data;
    char sub[64], kcid[23], raw_email[X3KC_EMAIL_MAX + 2], email_buf[X3KC_EMAIL_MAX + 1];
    char reason_buf[X3KC_REASON_MAX + 1], username[256];
    const char *email = NULL;
    enum x3kc_result res;

    if (!rec_returned(r))
        return;
    res = x3kc_map_grant(result);
    if (result == KC_CLIENT_REFUSED)
        log_module(KC_LOG, LOG_ERROR, "Keycloak refused X3's own client %s (wrong keycloak_client_secret, or the client may not use the password grant); logins fail until that is fixed.",
                   nickserv_conf.keycloak_client_id);
    else if (res == X3KC_UNREACHABLE)
        failure_note("login check", result);
    if (res == X3KC_OK) {
        if (!token || !token->id_token
            || !kc_jwt_extract_sub(token->id_token, sub, sizeof(sub))
            || !kcid_from_uuid(sub, kcid)) {
            log_module(KC_LOG, LOG_ERROR, "Keycloak accepted a login but its answer has no usable user id (an ID token with a UUID \"sub\"); is the openid scope allowed for client %s?",
                       nickserv_conf.keycloak_client_id);
            res = X3KC_UNREACHABLE;
        } else if (!kc_jwt_extract_claim(token->id_token, "preferred_username", username, sizeof(username))) {
            log_module(KC_LOG, LOG_ERROR, "Keycloak accepted a login for %s but its ID token has no \"preferred_username\"; is the profile scope allowed for client %s?  Refused.",
                       r->account, nickserv_conf.keycloak_client_id);
            res = X3KC_UNREACHABLE;
        } else if (irccasecmp(username, r->account)) {
            /* The password grant can log a user in by another name than
             * its username (its email address, with "Login with email"
             * on), and X3 folds names as IRC does, Keycloak as it does:
             * two Keycloak users must never end up on one handle. */
            log_module(KC_LOG, LOG_WARNING, "Keycloak accepted the password given for %s as its user \"%s\" (id %s), which is another name; refused.",
                       r->account, username, kcid);
            res = X3KC_REJECTED;
        } else if (kc_jwt_extract_claim(token->id_token, "email", raw_email, sizeof(raw_email))) {
            email = seam_email(raw_email, email_buf);
        }
    }
    rec_done(r, res, res == X3KC_OK ? kcid : NULL, email,
             x3kc_clean_reason(reason, reason_buf));
}

void
x3kc_login(const char *account, const char *password, x3kc_login_cb cb, void *data)
{
    struct x3kc_rec *r;

    if (!kc_configured || !account || !password) {
        cb(X3KC_UNREACHABLE, NULL, NULL, NULL, data);
        return;
    }
    if (seam_full()) {
        cb(X3KC_BUSY, NULL, NULL, NULL, data);
        return;
    }
    if (!(r = rec_new(KIND_LOGIN, data))) {
        cb(X3KC_UNREACHABLE, NULL, NULL, NULL, data);
        return;
    }
    r->cb.login = cb;
    /* For the username check when Keycloak accepts. */
    if (!(r->account = strdup(account))) {
        rec_answer(r, X3KC_UNREACHABLE, NULL, NULL, NULL);
        return;
    }
    if (rec_arm(r) != 0)
        return;
    rec_count(r);
    /* kc copies the password into the request; nothing here keeps it. */
    if (kc_user_verify_password(account, password, login_cb, r) != 0)
        rec_done(r, X3KC_UNREACHABLE, NULL, NULL, NULL);
    /* else r is kc's: it may be answered and freed already. */
}

/* ------------------------------------------------------------------ */
/* Look-up                                                            */
/* ------------------------------------------------------------------ */

static void
lookup_cb(int result, const struct kc_user *user, void *data)
{
    struct x3kc_rec *r = data;
    char kcid[23], email_buf[X3KC_EMAIL_MAX + 1];
    const char *email = NULL;
    enum x3kc_result res;

    if (!rec_returned(r))
        return;
    if (result == KC_SUCCESS && user) {
        if (!user->id || !kcid_from_uuid(user->id, kcid)) {
            log_module(KC_LOG, LOG_ERROR, "Keycloak answered a user look-up with a user whose id is no UUID.");
            res = X3KC_UNREACHABLE;
        } else {
            res = X3KC_OK;
            email = seam_email(user->email, email_buf);
        }
    } else if (result == KC_NOT_FOUND) {
        res = X3KC_NOT_FOUND;
    } else {
        failure_note("user look-up", result);
        res = X3KC_UNREACHABLE;
    }
    rec_done(r, res, res == X3KC_OK ? kcid : NULL, email, NULL);
}

static void
lookup_start(struct x3kc_rec *r, const char *account)
{
    /* A look-up that may queue (a stamp's) has its deadline from here,
     * as a delete does: one that waited behind a netjoin's look-ups still
     * gets its full keycloak_timeout with Keycloak. */
    if (r->arm_at_start && rec_arm(r) != 0)
        return;
    rec_count(r);
    /* kc copies account before it can call back (and free r with it). */
    if (kc_user_get(account, lookup_cb, r) != 0)
        rec_done(r, X3KC_UNREACHABLE, NULL, NULL, NULL);
}

void
x3kc_lookup(const char *account, int queue, x3kc_user_cb cb, void *data)
{
    struct x3kc_rec *r;

    if (!kc_configured || !account) {
        cb(X3KC_UNREACHABLE, NULL, NULL, data);
        return;
    }
    if (!queue && seam_full()) {
        cb(X3KC_BUSY, NULL, NULL, data);
        return;
    }
    if (!(r = rec_new(KIND_LOOKUP, data))) {
        cb(X3KC_UNREACHABLE, NULL, NULL, data);
        return;
    }
    r->cb.user = cb;
    r->arm_at_start = queue ? 1 : 0;
    if (!queue && rec_arm(r) != 0)
        return;
    /* Behind any look-up already waiting, so its queue stays first come,
     * first served (ahead of waiting deletes); and only within the queued
     * calls' share of the slots. */
    if (queue && queue_must_wait(0)) {
        if (!(r->account = strdup(account))) {
            rec_answer(r, X3KC_UNREACHABLE, NULL, NULL, NULL);
            return;
        }
        queue_append(r);
        log_module(KC_LOG, LOG_DEBUG, "Keycloak look-up of %s queued (%u in flight).", account, inflight);
        return;
    }
    lookup_start(r, account);
}

/* ------------------------------------------------------------------ */
/* Writes                                                             */
/* ------------------------------------------------------------------ */

/* A write's result, logged.  A note on X3KC_REJECTED: Keycloak refusing
 * X3's service account a write is an HTTP 403, which the kc copied today
 * reports as KC_ERROR on these calls, the same as no answer or a 5xx; so
 * KC_ERROR is logged with the right to check, and answered as
 * unreachable.  x3kc_map_write() already maps KC_FORBIDDEN to
 * X3KC_REJECTED for a kc that tells a 403 apart. */
static enum x3kc_result
write_outcome(const char *what, const char *uuid, int result)
{
    enum x3kc_result res = x3kc_map_write(result);

    if (res == X3KC_REJECTED) {
        log_module(KC_LOG, LOG_DEBUG, "Keycloak refused the %s of user %s (kc result %d).", what, uuid, result);
        if (quiet_note(QUIET_FAILED))
            log_module(KC_LOG, LOG_ERROR, "Keycloak refused X3's service account the %s of user %s: it needs the realm-management role manage-users; further calls without an answer are counted, one line per %us.",
                       what, uuid, QUIET_SUMMARY_SECS);
    } else if (res == X3KC_UNREACHABLE) {
        /* Quietly, as failure_note(): an expiry run during an outage
         * sends up to keycloak_max_pending deletes at once. */
        log_module(KC_LOG, LOG_DEBUG, "Keycloak %s of user %s failed (kc result %d).", what, uuid, result);
        if (quiet_note(QUIET_FAILED)) {
            if (result == KC_ERROR)
                log_module(KC_LOG, LOG_ERROR, "Keycloak %s of user %s failed (no answer, or an error status; kc reports a refusal of X3's service account the same way: if Keycloak is up, check that client %s's service account has the realm-management role manage-users); further calls without an answer are counted, one line per %us.",
                           what, uuid, nickserv_conf.keycloak_client_id, QUIET_SUMMARY_SECS);
            else
                log_module(KC_LOG, LOG_WARNING, "Keycloak %s of user %s failed (kc result %d); further calls without an answer are counted, one line per %us.",
                           what, uuid, result, QUIET_SUMMARY_SECS);
        }
    } else if (res == X3KC_NOT_FOUND)
        log_module(KC_LOG, LOG_INFO, "Keycloak %s: user %s (or the group) does not exist.", what, uuid);
    return res;
}

static void
delete_cb(int result, void *data)
{
    struct x3kc_rec *r = data;

    if (!rec_returned(r))
        return;
    rec_done(r, write_outcome("delete", r->uuid, result), NULL, NULL, NULL);
}

/* A delete gets its slot: its deadline runs from here. */
static void
delete_start(struct x3kc_rec *r)
{
    if (rec_arm(r) != 0)
        return;
    rec_count(r);
    if (kc_user_delete(r->uuid, delete_cb, r) != 0)
        rec_done(r, X3KC_UNREACHABLE, NULL, NULL, NULL);
}

void
x3kc_delete(const char *kcid, x3kc_done_cb cb, void *data)
{
    struct x3kc_rec *r;
    char uuid[37];

    if (!kc_configured) {
        cb(X3KC_UNREACHABLE, data);
        return;
    }
    if (!kcid_to_uuid(kcid, uuid)) {
        log_module(KC_LOG, LOG_WARNING, "Keycloak delete refused: %s is no Keycloak id.", kcid ? kcid : "(none)");
        cb(X3KC_REJECTED, data);
        return;
    }
    if (!(r = rec_new(KIND_DELETE, data))) {
        cb(X3KC_UNREACHABLE, data);
        return;
    }
    r->cb.done = cb;
    memcpy(r->uuid, uuid, sizeof(uuid));
    /* Never BUSY: past the share of the slots it waits its turn, behind
     * every waiting look-up and delete (an expiry run can unregister
     * thousands of handles at once). */
    if (queue_must_wait(1)) {
        queue_append(r);
        log_module(KC_LOG, LOG_DEBUG, "Keycloak delete of user %s queued (%u in flight).", r->uuid, inflight);
        return;
    }
    delete_start(r);
}

static void
group_cache_clear(void)
{
    free(group_cache_path);
    free(group_cache_id);
    group_cache_path = group_cache_id = NULL;
}

static void oper_group_cb(int result, const struct kc_group *group, void *data);
static void oper_write_cb(int result, void *data);
static void oper_repr_cb(int result, json_t *repr, void *data);

/* Starts the next part of an oper level change: the group (looked up
 * first if its id is not known), then the attribute.  r is counted; after
 * a request has been started r is kc's and is not touched here again. */
static void
oper_step(struct x3kc_rec *r)
{
    int rc;

    if (r->group_path && !r->group_done) {
        if (!r->group_id) {
            if (r->group_path[0] != '/') {
                log_module(KC_LOG, LOG_ERROR, "keycloak_oper_group \"%s\" is not a group path (it must start with '/'); OpServ level changes are refused.",
                           r->group_path);
                rec_done(r, X3KC_REJECTED, NULL, NULL, NULL);
                return;
            }
            if (group_cache_id && group_cache_path && !strcmp(group_cache_path, r->group_path)
                && r->gen == kc_gen && !(r->group_id = strdup(group_cache_id))) {
                rec_done(r, X3KC_UNREACHABLE, NULL, NULL, NULL);
                return;
            }
        }
        if (!r->group_id) {
            r->step = STEP_GROUP_LOOKUP;
            rc = kc_group_get_by_path(r->group_path, oper_group_cb, r);
        } else {
            r->step = STEP_GROUP_CHANGE;
            rc = r->in_group
                ? kc_user_add_group(r->uuid, r->group_id, oper_write_cb, r)
                : kc_user_remove_group(r->uuid, r->group_id, oper_write_cb, r);
        }
    } else if (r->field) {
        r->step = STEP_REPR_GET;
        rc = kc_user_get_repr(r->uuid, oper_repr_cb, r);
    } else {
        rec_done(r, X3KC_OK, NULL, NULL, NULL);
        return;
    }
    if (rc != 0)
        rec_done(r, X3KC_UNREACHABLE, NULL, NULL, NULL);
}

static void
oper_group_cb(int result, const struct kc_group *group, void *data)
{
    struct x3kc_rec *r = data;

    if (!rec_returned(r))
        return;
    /* The group is missing when Keycloak says so (404), or answers with
     * no group or an id that is unusable in a URL.  Any other failure
     * (no admin token, no answer, an error status) is an outage: the call
     * is unreachable and nothing is cached, so the next call asks again. */
    if (result == KC_NOT_FOUND || result == KC_INVALID_RESPONSE
        || (result == KC_SUCCESS && (!group || !x3kc_safe_id(group->id)))) {
        log_module(KC_LOG, LOG_ERROR, "Keycloak group %s (keycloak_oper_group) could not be resolved (%s); OpServ level changes are refused until it can.",
                   r->group_path,
                   result == KC_NOT_FOUND ? "no such group"
                   : result == KC_INVALID_RESPONSE ? "Keycloak's answer names no group id"
                   : "an id that is unusable in a URL");
        rec_done(r, X3KC_REJECTED, NULL, NULL, NULL);
        return;
    }
    if (result != KC_SUCCESS) {
        log_module(KC_LOG, LOG_WARNING, "Keycloak look-up of group %s (keycloak_oper_group) failed (kc result %d).",
                   r->group_path, result);
        rec_done(r, X3KC_UNREACHABLE, NULL, NULL, NULL);
        return;
    }
    if (!(r->group_id = strdup(group->id))) {
        rec_done(r, X3KC_UNREACHABLE, NULL, NULL, NULL);
        return;
    }
    /* Keep it while kc runs on the same configuration and the setting is
     * the one this call was made with. */
    if (r->gen == kc_gen && !strcmp(nickserv_conf.keycloak_oper_group, r->group_path)) {
        char *path = strdup(r->group_path), *id = strdup(group->id);
        if (path && id) {
            group_cache_clear();
            group_cache_path = path;
            group_cache_id = id;
        } else {
            free(path);
            free(id);
        }
    }
    oper_step(r);
}

static void
oper_write_cb(int result, void *data)
{
    struct x3kc_rec *r = data;
    enum x3kc_result res;

    if (!rec_returned(r))
        return;
    if (r->step == STEP_GROUP_CHANGE) {
        res = write_outcome(r->in_group ? "oper group add" : "oper group removal", r->uuid, result);
        if (res == X3KC_NOT_FOUND && group_cache_id && !strcmp(group_cache_id, r->group_id))
            group_cache_clear();        /* maybe the group went: look it up again next time */
        if (res != X3KC_OK) {
            rec_done(r, res, NULL, NULL, NULL);
            return;
        }
        r->group_done = 1;
        oper_step(r);
        return;
    }
    rec_done(r, write_outcome("level attribute update", r->uuid, result), NULL, NULL, NULL);
}

static void
oper_repr_cb(int result, json_t *repr, void *data)
{
    struct x3kc_rec *r = data;
    enum x3kc_result res;

    if (!rec_returned(r))
        return;
    if (result != KC_SUCCESS || !repr) {
        res = write_outcome("read (for the level attribute)", r->uuid, result);
        rec_done(r, res == X3KC_OK ? X3KC_UNREACHABLE : res, NULL, NULL, NULL);
        return;
    }
    /* repr is borrowed for this call and may be changed in place
     * (kc_user_repr_cb); kc_user_update() serialises it before it returns. */
    if (x3kc_repr_set_level(repr, r->field, r->level) != 0) {
        log_module(KC_LOG, LOG_ERROR, "Keycloak user %s: its representation has no usable \"attributes\" map; level attribute not written.",
                   r->uuid);
        rec_done(r, X3KC_UNREACHABLE, NULL, NULL, NULL);
        return;
    }
    r->step = STEP_UPDATE;
    if (kc_user_update(r->uuid, repr, oper_write_cb, r) != 0)
        rec_done(r, X3KC_UNREACHABLE, NULL, NULL, NULL);
}

void
x3kc_set_oper(const char *kcid, int in_group, unsigned int level, x3kc_done_cb cb, void *data)
{
    const char *group = nickserv_conf.keycloak_oper_group;
    const char *field = nickserv_conf.keycloak_field_oslevel;
    struct x3kc_rec *r;
    char uuid[37];

    if ((!group || !*group) && (!field || !*field)) {
        cb(X3KC_OK, data);
        return;
    }
    if (!kc_configured) {
        cb(X3KC_UNREACHABLE, data);
        return;
    }
    if (!kcid_to_uuid(kcid, uuid)) {
        log_module(KC_LOG, LOG_WARNING, "Keycloak oper level change refused: %s is no Keycloak id.", kcid ? kcid : "(none)");
        cb(X3KC_REJECTED, data);
        return;
    }
    if (seam_full()) {
        cb(X3KC_BUSY, data);
        return;
    }
    if (!(r = rec_new(KIND_SET_OPER, data))) {
        cb(X3KC_UNREACHABLE, data);
        return;
    }
    r->cb.done = cb;
    memcpy(r->uuid, uuid, sizeof(uuid));
    r->in_group = in_group;
    r->level = level;
    /* The settings as they are now: a rehash may replace them meanwhile. */
    if ((group && *group && !(r->group_path = strdup(group)))
        || (field && *field && !(r->field = strdup(field)))) {
        rec_answer(r, X3KC_UNREACHABLE, NULL, NULL, NULL);
        return;
    }
    if (rec_arm(r) != 0)
        return;
    rec_count(r);
    oper_step(r);
}

/* ------------------------------------------------------------------ */
/* Start, rehash, exit                                                */
/* ------------------------------------------------------------------ */

static void
x3kc_forget_applied(void)
{
    free(applied_url);
    free(applied_realm);
    free(applied_client_id);
    free(applied_secret);
    applied_url = applied_realm = applied_client_id = applied_secret = NULL;
    applied_timeout = 0;
}

static int
x3kc_differs(const char *applied, const char *wanted)
{
    return !applied || strcmp(applied, wanted) != 0;
}

/* kc is restarted or turned off: every call in flight is answered
 * X3KC_UNREACHABLE now (their answers under the old configuration are
 * dropped when they come), then kc_keycloak_shutdown(), whose answers to
 * operations still queued for an admin token find their records answered
 * and are dropped too. */
static void
x3kc_stop(void)
{
    kc_configured = 0;
    kc_gen++;
    group_cache_clear();
    seam_abort_all();
    kc_keycloak_shutdown();
}

/* Process exit only.  Every record is dead first: no caller is answered
 * from here on (their data is being torn down).  Then kc: the keycloak
 * layer answers queued token waiters at once (dead records, freed), the
 * HTTP layer drops what is in flight without calling back, so whatever kc
 * still held is freed here. */
static void
x3kc_exit(UNUSED_ARG(void *extra))
{
    struct x3kc_rec *r, *next;
    int was_configured = kc_configured;

    kc_configured = 0;
    for (r = rec_head; r; r = r->next) {
        r->dead = 1;
        r->answered = 1;
        rec_disarm(r);
    }
    {
        unsigned int deletes = 0;

        for (r = delete_queue.head; r; r = r->qnext)
            deletes++;
        if (deletes) {
            log_module(KC_LOG, LOG_WARNING, "Exiting with %u Keycloak user delete(s) still waiting their turn; they are not sent, and those users still exist in Keycloak (ids follow at INFO).",
                       deletes);
            for (r = delete_queue.head; r; r = r->qnext)
                log_module(KC_LOG, LOG_INFO, "Keycloak delete not sent at exit: user %s.", r->uuid);
        }
    }
    while ((r = queue_first()) != NULL)
        queue_remove(r);
    if (quiet_summary_timer) {
        x3_kc_get_event_ops()->timer_cancel(quiet_summary_timer);
        quiet_summary_timer = NULL;
    }
    quiet_count[QUIET_DEADLINE] = quiet_count[QUIET_FAILED] = 0;
    if (was_configured)
        kc_keycloak_shutdown();
    if (kc_running) {
        kc_shutdown();
        kc_running = 0;
        x3_kc_adapter_cleanup();
    }
    for (r = rec_head; r; r = next) {
        next = r->next;
        rec_uncount(r);
        rec_free(r);
    }
    group_cache_clear();
    x3kc_forget_applied();
}

void
x3kc_init(void)
{
    static int registered;

    if (!registered) {
        reg_exit_func(x3kc_exit, NULL);
        registered = 1;
    }
}

int
x3kc_async_dns(const char **version)
{
    const curl_version_info_data *info = curl_version_info(CURLVERSION_NOW);

    *version = info && info->version ? info->version : "unknown version";
    return info && (info->features & CURL_VERSION_ASYNCHDNS) ? 1 : 0;
}

void
x3kc_configure(void)
{
    const struct nickserv_config *conf = &nickserv_conf;
    struct kc_config cfg;
    int restart;

    if (!conf->keycloak_enable || conf->keycloak_refused) {
        /* Turned off by a rehash, or a rehash's settings were refused:
         * drop the configuration (see below for what happens to requests
         * in flight).  Never started: nothing of kc is touched, so no
         * libcurl handle and no keycloak log.  Refused: every call is
         * answered X3KC_UNREACHABLE (kc_configured is 0) until a rehash
         * brings settings nickserv_conf_read() accepts. */
        if (kc_configured) {
            x3kc_stop();
            x3kc_forget_applied();
            if (conf->keycloak_enable)
                log_module(KC_LOG, LOG_ERROR, "Keycloak logins stopped: the rehashed keycloak_* settings were refused; logins answer that the account server cannot be reached until a rehash with settings X3 accepts.");
            else
                log_module(KC_LOG, LOG_INFO, "Keycloak logins off (keycloak_enable 0).");
        }
        return;
    }

    if (!kc_running) {
        x3_kc_adapter_init();
        KC_LOG = log_register_type("keycloak", NULL);
        if (kc_init(x3_kc_get_event_ops(), x3_kc_get_log_ops()) != 0) {
            log_module(KC_LOG, LOG_ERROR, "Unable to start the Keycloak client; Keycloak logins will fail until a rehash starts it.");
            return;
        }
        kc_running = 1;
    }

    if (kc_configured
        && !x3kc_differs(applied_url, conf->keycloak_url)
        && !x3kc_differs(applied_realm, conf->keycloak_realm)
        && !x3kc_differs(applied_client_id, conf->keycloak_client_id)
        && !x3kc_differs(applied_secret, conf->keycloak_client_secret)
        && applied_timeout == conf->keycloak_timeout) {
        /* kc stays.  A changed oper group is looked up afresh; a larger
         * keycloak_max_pending lets waiting look-ups start. */
        if (group_cache_path && strcmp(group_cache_path, conf->keycloak_oper_group))
            group_cache_clear();
        pump();
        return;
    }

    /* A setting kc uses changed.  kc_keycloak_shutdown() answers the
     * operations still queued for an admin token at once (KC_TOKEN_ERROR),
     * drops the cached token, and does NOT cancel requests already in
     * flight: each of those still calls back later, exactly once, with the
     * old configuration's result.  Their callback data is a seam record,
     * which x3kc_stop() has answered (X3KC_UNREACHABLE) and which stays
     * until that late callback frees it.  The HTTP layer (kc_shutdown()) is
     * left running on purpose: it would drop those transfers without ever
     * calling back.  It is shut down only at process exit (x3kc_exit()). */
    restart = kc_configured;
    if (kc_configured)
        x3kc_stop();
    x3kc_forget_applied();

    memset(&cfg, 0, sizeof(cfg));
    cfg.base_url = conf->keycloak_url;
    cfg.realm = conf->keycloak_realm;
    cfg.client_id = conf->keycloak_client_id;
    cfg.client_secret = conf->keycloak_client_secret;
    cfg.timeout_ms = (long)conf->keycloak_timeout;
    if (kc_keycloak_init(&cfg) != 0) {
        log_module(KC_LOG, LOG_ERROR, "Unable to configure the Keycloak client for %s/realms/%s; Keycloak logins will fail until a rehash.", conf->keycloak_url, conf->keycloak_realm);
        return;
    }
    kc_configured = 1;
    applied_url = strdup(conf->keycloak_url);
    applied_realm = strdup(conf->keycloak_realm);
    applied_client_id = strdup(conf->keycloak_client_id);
    applied_secret = strdup(conf->keycloak_client_secret);
    applied_timeout = conf->keycloak_timeout;

    /* Never the secret. */
    log_module(KC_LOG, LOG_INFO, "Keycloak logins %s: realm %s/realms/%s, client %s, timeout %u ms.",
               restart ? "reconfigured" : "on", conf->keycloak_url, conf->keycloak_realm,
               conf->keycloak_client_id, conf->keycloak_timeout);
}
