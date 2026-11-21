/* x3kc.h - X3's Keycloak backend
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
 * x3kc.c is built only with WITH_KEYCLOAK (configure adds it to
 * MODULE_OBJS).  This header may be included in every build: the result
 * enum and the callback types are always declared, so code shared with
 * LDAP mode can use them; the functions are declared only with
 * WITH_KEYCLOAK, so a call to one in a build without Keycloak fails to
 * compile rather than to link.  There are no stubs: a build without
 * Keycloak refuses keycloak_enable at load, so only the LDAP and local
 * paths run there, and code that calls the seam sits under
 * #ifdef WITH_KEYCLOAK.  Include it after config.h (common.h brings it).
 * It includes no X3 header, so x3kc-test can use it.
 */

#ifndef X3KC_H
#define X3KC_H

enum x3kc_result {
    X3KC_OK, X3KC_BAD_PASSWORD, X3KC_DISABLED, X3KC_NOT_SET_UP,
    X3KC_NOT_FOUND, X3KC_REJECTED, X3KC_BUSY, X3KC_UNREACHABLE
};

/* Every call below invokes its callback exactly once, possibly before it
 * returns.  `kcid` is the compact 22-character id.  Strings passed to a
 * callback are valid only during it; `email` and `reason` may be NULL.
 *
 * More of the contract:
 *   - Each call is answered within keycloak_timeout ms of being made
 *     (X3KC_UNREACHABLE at that deadline if Keycloak has not answered; a
 *     later answer is dropped).  A call made of several requests (set_oper)
 *     has one deadline for the whole call.
 *   - Over keycloak_max_pending requests in flight a call is answered
 *     X3KC_BUSY at once, except x3kc_lookup() with `queue` set, which waits
 *     its turn (still within its deadline).  Queued look-ups fill at most
 *     x3kc_queue_slots() of the slots, so the calls that do not queue
 *     (logins above all) keep a reserve while look-ups wait.
 *   - With Keycloak off, or kc not running, a call is answered
 *     X3KC_UNREACHABLE at once.  So is every call in flight when a rehash
 *     restarts kc or turns Keycloak off.
 *   - At process exit nothing is answered: the callbacks' data is being
 *     torn down.
 *   - A callback may call any x3kc_* function again.
 *   - `reason` (Keycloak's error_description) has its control characters
 *     removed and every '$' doubled (it is meant for a reply, where X3
 *     expands "$x" codes), and is at most 200 bytes; `email` is passed only if it looks
 *     like an address (else NULL); `kcid` only if Keycloak's id converts. */
typedef void (*x3kc_login_cb)(enum x3kc_result res, const char *kcid, const char *email,
                              const char *reason, void *data);
typedef void (*x3kc_user_cb)(enum x3kc_result res, const char *kcid, const char *email, void *data);
typedef void (*x3kc_done_cb)(enum x3kc_result res, void *data);

#ifdef WITH_KEYCLOAK

/* Brings the Keycloak client in line with the nickserv block's keycloak_*
 * settings, which nickserv_conf_read() has just read and checked.  Called
 * at the end of every nickserv_conf_read() and from init_nickserv(); a
 * call that finds nothing changed does nothing.  With keycloak_refused set
 * it leaves Keycloak unconfigured (every call answered X3KC_UNREACHABLE). */
void x3kc_configure(void);

/* 1 if the libcurl X3 runs with resolves names without blocking
 * (CURL_VERSION_ASYNCHDNS: the threaded resolver or c-ares).  Without it a
 * slow or unanswered DNS look-up for the Keycloak host would stall all of
 * X3 for as long as the look-up takes, so Keycloak mode is refused.
 * *version: libcurl's version string, for the log. */
int x3kc_async_dns(const char **version);

/* Registers the seam's exit function.  init_nickserv() calls it right
 * after registering nickserv_db_cleanup, so that at exit the seam lets go
 * of its callers' data (and shuts kc down) before NickServ's data is
 * freed, whenever Keycloak was first turned on. */
void x3kc_init(void);

/* Checks account's password with a password grant.  On X3KC_OK, kcid is
 * the user's id (from the ID token's "sub") and email the token's "email"
 * claim (NULL when absent).  reason is Keycloak's own text for a refusal,
 * when it gave one.  X3KC_REJECTED: Keycloak accepted the password, but
 * for a user whose username ("preferred_username") is not account under
 * IRC case folding (logged).  The password is not kept. */
void x3kc_login(const char *account, const char *password, x3kc_login_cb cb, void *data);

/* Looks a Keycloak user up by name: X3KC_OK with its id and email, or
 * X3KC_NOT_FOUND. */
void x3kc_lookup(const char *account, int queue, x3kc_user_cb cb, void *data);

/* Deletes the Keycloak user with this id. */
void x3kc_delete(const char *kcid, x3kc_done_cb cb, void *data);

/* Puts the user in or out of keycloak_oper_group (when set) and writes
 * level to the attribute keycloak_field_oslevel (when set; level 0
 * removes it), in that order.  X3KC_OK only if every configured part
 * succeeded; both keys empty is X3KC_OK without a request. */
void x3kc_set_oper(const char *kcid, int in_group, unsigned int level, x3kc_done_cb cb, void *data);

/* The password grant's kc result as a seam result.  Pure; unit-tested. */
enum x3kc_result x3kc_map_grant(int kc_result);

#endif /* WITH_KEYCLOAK */

#endif /* X3KC_H */
