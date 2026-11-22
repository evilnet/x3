#ifndef KCID_H
#define KCID_H

/* Keycloak user ids in two forms: the 36-character UUID Keycloak uses, and
 * the 22-character unpadded base64url form the ircd announces and saxdb
 * stores.  Plain C, no X3 headers, so the standalone test links it alone. */

/* UUID (dashes optional, either case) -> 22 base64url characters.
 * Returns 1 on success, 0 if uuid is not exactly 32 hex digits. */
int kcid_from_uuid(const char *uuid, char out[23]);

/* 22 base64url characters -> lower-case 8-4-4-4-12 UUID.  Returns 1 on
 * success, 0 for anything that is not exactly 22 valid characters -- and
 * for a last character whose 4 spare bits are not 0 (a UUID has 128 bits,
 * 22 characters carry 132): only the canonical form decodes, so two
 * strings never stand for one user. */
int kcid_to_uuid(const char *compact, char out[37]);

/* The canonical form of a compact id that may have spare bits set in its
 * last character (written by something other than the ircd or
 * kcid_from_uuid()): out = the id with them cleared.  Returns 1, or 0 when
 * compact is not 22 base64url characters (out untouched).  Every id X3
 * takes in -- REBIND, x3.db, an account stamp -- goes through this, so the
 * ids X3 holds compare equal exactly when they name the same user. */
int kcid_canonical(const char *compact, char out[23]);

/* What a login does with the Keycloak id it carries, once its account name
 * is the Keycloak user's: an id an ircd announced in an account stamp, or
 * the id of a password grant X3 made itself (AUTH, login-on-connect, SASL
 * PLAIN).  nickserv.c acts on the verdict (handle_kcid_decide()). */
enum kcid_verdict {
    KCID_PASS,              /* the stored id: go on */
    KCID_ADOPT,             /* none stored, LDAP or local mode: store it once the login
                             * goes through */
    KCID_RESET,             /* a recreated user, keycloak_id_reset on: the handle starts over */
    KCID_REFUSE_STALE,      /* an id this handle's binding replaced: refused */
    KCID_REFUSE_MISMATCH,   /* another id, keycloak_id_reset off: refused */
    KCID_REFUSE_SUSPENDED,  /* another id, keycloak_id_reset on, handle suspended: refused */
    KCID_REFUSE_UNBOUND     /* none stored, Keycloak mode: refused (an oper binds with REBIND) */
};

/* The decision for id against a handle whose stored id is stored (NULL for
 * none).  replaced: id is one the handle's binding replaced; reset_on:
 * keycloak_id_reset; suspended: the handle is; keycloak_mode:
 * keycloak_enable.  A replaced id is refused first, stored or not: after
 * REBIND * nothing is stored, and the id the handle was cleared of must not
 * be bound again.  With none stored, Keycloak mode refuses
 * (KCID_REFUSE_UNBOUND): the binding script gives every handle it can its
 * id at the switch, so a handle still unbound is one it found no Keycloak
 * user for, or one an oper unbound on purpose, and a namesake Keycloak
 * user is not proof that it is the same account; an oper binds it with
 * REBIND.  LDAP and local mode adopt an announced id as master does. */
enum kcid_verdict kcid_decide(const char *stored, int replaced, int reset_on,
                              int suspended, int keycloak_mode, const char *id);

/* The decision for an account stamp that carries NO Keycloak id, for a
 * handle X3 has (handle_account()).  stored: the handle's id (NULL for
 * none); keycloak_mode: keycloak_enable; stamp_ts: the stamp's account
 * timestamp (0 for none); registered: the handle's registration date.
 * KCID_REFUSE_UNBOUND in Keycloak mode for a handle with no id stored,
 * unless stamp_ts is non-zero and equal to registered -- X3's own stamp
 * (X3 stamps a login it makes as name:registered, with no id; a burst
 * replays it after a restart).  Any other no-id stamp comes from an ircd's
 * own login (EXTENDED_ACCOUNTS off, an ID token without a UUID sub, an
 * impersonated SASL_TRUSTED_AUTHZID login, AC R with no timestamp slot),
 * and a Keycloak user of the handle's name is no proof that it owns the
 * handle; an oper binds it with REBIND.  KCID_PASS otherwise: LDAP and
 * local mode, and a handle with an id stored (fail open, as before). */
enum kcid_verdict kcid_decide_no_id(const char *stored, int keycloak_mode,
                                    unsigned long stamp_ts, unsigned long registered);

/* The oper notices for refused ids (NSMSG_IDENTITY_*), rate-limited: the
 * first goes out at once and opens a minute; the ones that follow within
 * it are held and counted, and the count goes out when the minute is over
 * (which opens the next one).  A minute with nothing held lets the next
 * notice out at once again.  Every refusal is logged either way. */
struct kcid_notice_limit {
    long window_start;          /* 0: no minute open */
    unsigned int held;          /* notices held in the open minute */
};
#define KCID_NOTICE_WINDOW 60

/* 1: send this notice now; 0: it was held (counted). */
int kcid_notice_take(struct kcid_notice_limit *lim, long now);

/* When the held count is due (the end of the open minute), or 0 when
 * nothing is held. */
long kcid_notice_due(const struct kcid_notice_limit *lim);

/* At the end of the minute: returns the count held (0 for none) and
 * starts the next minute when there was one, so a steady stream gives one
 * count per minute. */
unsigned int kcid_notice_flush(struct kcid_notice_limit *lim, long now);

#endif
