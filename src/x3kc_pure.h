/* x3kc_pure.h - the pure pieces of X3's Keycloak seam (x3kc.c)
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
 * No X3 headers and no network: x3kc-test links x3kc_pure.c alone.
 * Built only with WITH_KEYCLOAK.  x3kc_map_grant() is declared in x3kc.h.
 */

#ifndef X3KC_PURE_H
#define X3KC_PURE_H

#include <jansson.h>
#include "x3kc.h"

/* Longest reason (Keycloak's error_description) handed to a callback, in
 * bytes, without the NUL. */
#define X3KC_REASON_MAX 200

/* Longest email address accepted from Keycloak, in bytes, without the NUL.
 * X3 has no limit of its own (SET EMAIL is bounded only by the IRC line);
 * this is RFC 5321's limit for an address in a mail path. */
#define X3KC_EMAIL_MAX 254

/* What a write (delete, group change, user update) answered:
 * KC_SUCCESS -> X3KC_OK; KC_NOT_FOUND -> X3KC_NOT_FOUND (the user or the
 * group does not exist); KC_FORBIDDEN -> X3KC_REJECTED (Keycloak refused
 * X3's service account; see the note in x3kc.c: the kc copied today reports
 * an HTTP 403 on these calls as KC_ERROR); everything else ->
 * X3KC_UNREACHABLE. */
enum x3kc_result x3kc_map_write(int kc_result);

/* The AuthServ reply (a message id) for a password login's answer that
 * ends an AUTH before X3 looks at the handle: NSMSG_KC_DISABLED,
 * NSMSG_KC_NOT_SET_UP (takes the reason), NSMSG_KC_BUSY, and NSMSG_KC_FAIL
 * for an outage and for any answer a login is not supposed to get.  NULL
 * for X3KC_OK and X3KC_BAD_PASSWORD, which go on to the handle's checks
 * (the latter to the wrong-password path). */
const char *x3kc_login_reply(enum x3kc_result res);

/* 1 for the one answer that counts as a failed password -- the
 * wrong-password reply, the failpw hooks, the auth policer --
 * X3KC_BAD_PASSWORD; 0 for every other. */
int x3kc_failed_password(enum x3kc_result res);

/* How many requests in flight queued look-ups may fill, for a cap of
 * max_pending: the cap less a reserve of max(1, max_pending / 4) kept for
 * calls that do not queue (logins above all), but at least 1, so that
 * queued look-ups always make progress.  0 for a cap of 0. */
unsigned int x3kc_queue_slots(unsigned int max_pending);

/* The hostmask a new owner gets from a login-on-connect or SASL request's
 * "ident@host:ip" ("ident@[host]:ip" when the host has a ':'): the mask
 * AUTH seeds for a connected user, generate_hostmask() with
 * GENMASK_OMITNICK|GENMASK_NO_HIDING|GENMASK_ANY_IDENT -- "*@" and the host
 * with its leading labels wildcarded (one or two labels kept as they are,
 * three -> the last two, more -> the last three), or for a host that is an
 * address the connection address's /16 (IPv4) or /48 (IPv6).  1 with the
 * mask in out, 0 if userhost is not of that form or the mask does not fit.
 * (X3's generate_hostmask() prints IPv6 words in network byte order; this
 * prints them as written.) */
int x3kc_loc_mask(const char *userhost, char *out, size_t outlen);

/* Copies in to out without control characters (bytes below 0x20, and 0x7f),
 * with every '$' doubled (X3 expands "$x" codes in replies; "$$" shows a
 * '$'), at most X3KC_REASON_MAX bytes, never ending in a cut UTF-8
 * character or half a "$$".  Returns out, or NULL when in is NULL or
 * nothing is left.  The result is meant for a reply, not a log line. */
const char *x3kc_clean_reason(const char *in, char out[X3KC_REASON_MAX + 1]);

/* Copies in to out if it may be an email address: 1 to X3KC_EMAIL_MAX
 * bytes, no control character, no space, an '@'.  Returns out, or NULL
 * (in refused).  x3kc.c also applies X3's own valid_email() rule. */
const char *x3kc_clean_email(const char *in, char out[X3KC_EMAIL_MAX + 1]);

/* 1 if id (a group id Keycloak sent) is 1 to 64 characters from
 * [A-Za-z0-9_-] -- safe to put in a URL path as it is -- else 0. */
int x3kc_safe_id(const char *id);

/* Sets the user attribute attr in the user representation repr to the one
 * value "<level>" (Keycloak attributes are arrays of strings), or removes
 * it when level is 0.  Everything else in repr stays as read.  A missing or
 * null "attributes" counts as an empty one: set creates the map, remove
 * leaves it alone.  A removal keeps the (possibly now empty) map, since a
 * user PUT without "attributes" would leave them all unchanged.
 * Returns 0, or -1 with repr unchanged: repr is not an object, its
 * "attributes" is neither an object nor null, attr is NULL or empty, or an
 * allocation failed. */
int x3kc_repr_set_level(json_t *repr, const char *attr, unsigned int level);

/* What the answer to the Keycloak look-up for an account stamp does
 * (handle_account(), for a name X3 had no handle for, with
 * keycloak_autocreate on). */
enum x3kc_stamp_step {
    X3KC_STAMP_DROP,            /* the user left, or is logged in to X3 by now: nothing */
    X3KC_STAMP_UNKNOWN,         /* Keycloak has no user of that name (and X3 still has no
                                 * handle): unknown stamp, as before */
    X3KC_STAMP_RETRY_LATER,     /* no usable answer (outage, deadline, ...) and still no
                                 * handle: the user stays unbound in X3; the next event for
                                 * it tries again */
    X3KC_STAMP_ID_MISMATCH,     /* the stamp announced another id than Keycloak's user of
                                 * that name has: ignored (and logged) */
    X3KC_STAMP_KNOWN,           /* a handle of that name appeared meanwhile, and the stamp
                                 * announced an id or Keycloak gave none: the stamp as it came
                                 * goes the way of one for a known handle (handle_account()) */
    X3KC_STAMP_BIND_LOOKED_UP,  /* a handle of that name appeared meanwhile, the stamp
                                 * announced no id, Keycloak gave one: the caller lets the
                                 * stamp go on (handle_account()) only if that id is the
                                 * handle's; a handle with no id is refused as unlinked, one
                                 * with another id is left alone -- a looked-up id never binds
                                 * or resets a handle */
    X3KC_STAMP_OLD,             /* no id announced, a non-zero account timestamp, and still
                                 * no handle: X3's own stamp for a handle it no longer has
                                 * (deleted, perhaps registered again since); never created
                                 * from: the user stays unbound */
    X3KC_STAMP_CREATE           /* confirmed and still no handle: create it, bind the user */
};

/* Whether a stamp for a name X3 has no handle for may create one, by its
 * form alone: it announced a Keycloak id, or it carries no account
 * timestamp (0; the fork's own Keycloak logins stamp 0).  A non-zero
 * timestamp without an id is X3's own stamp (name:registered): the handle
 * it named is gone, and the account timestamp exists to refuse exactly
 * that stamp -- a handle made now would be a different account. */
int x3kc_stamp_may_create(const char *announced_id, unsigned long timestamp);

/* The step for look-up answer res (found_id: the id it carries, if any),
 * given whether the stamped user is still connected (user_present) and
 * already logged in to X3 (user_authed), the id the stamp announced
 * (announced_id; NULL or "" for none), the stamp's account timestamp (0
 * for none) and whether X3 has a handle of the name now (handle_exists).
 * A stamp x3kc_stamp_may_create() refuses is never CREATE.  Only X3KC_OK with a non-empty id confirms the
 * account; an announced id that differs from a confirmed one is refused
 * before anything else is done with the confirmation. */
enum x3kc_stamp_step x3kc_stamp_step(enum x3kc_result res, int user_present, int user_authed,
                                     const char *announced_id, unsigned long timestamp,
                                     const char *found_id, int handle_exists);

#endif /* X3KC_PURE_H */
