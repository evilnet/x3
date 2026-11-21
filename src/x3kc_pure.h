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

/* How many requests in flight queued look-ups may fill, for a cap of
 * max_pending: the cap less a reserve of max(1, max_pending / 4) kept for
 * calls that do not queue (logins above all), but at least 1, so that
 * queued look-ups always make progress.  0 for a cap of 0. */
unsigned int x3kc_queue_slots(unsigned int max_pending);

/* Copies in to out without control characters (bytes below 0x20, and 0x7f),
 * at most X3KC_REASON_MAX bytes, never ending in a cut UTF-8 character.
 * Returns out, or NULL when in is NULL or nothing is left. */
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

#endif /* X3KC_PURE_H */
