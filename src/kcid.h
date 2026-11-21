#ifndef KCID_H
#define KCID_H

/* Keycloak user ids in two forms: the 36-character UUID Keycloak uses, and
 * the 22-character unpadded base64url form the ircd announces and saxdb
 * stores.  Plain C, no X3 headers, so the standalone test links it alone. */

/* UUID (dashes optional, either case) -> 22 base64url characters.
 * Returns 1 on success, 0 if uuid is not exactly 32 hex digits. */
int kcid_from_uuid(const char *uuid, char out[23]);

/* 22 base64url characters -> lower-case 8-4-4-4-12 UUID.  Returns 1 on
 * success, 0 for anything that is not exactly 22 valid characters. */
int kcid_to_uuid(const char *compact, char out[37]);

/* What a login does with the Keycloak id it carries, once its account name
 * is the Keycloak user's: an id an ircd announced in an account stamp, or
 * the id of a password grant X3 made itself (AUTH, login-on-connect, SASL
 * PLAIN).  nickserv.c acts on the verdict (handle_kcid_decide()). */
enum kcid_verdict {
    KCID_PASS,              /* the stored id: go on */
    KCID_ADOPT,             /* none stored: store it once the login goes through */
    KCID_RESET,             /* a recreated user, keycloak_id_reset on: the handle starts over */
    KCID_REFUSE_STALE,      /* an id this handle's binding replaced: refused */
    KCID_REFUSE_MISMATCH,   /* another id, keycloak_id_reset off: refused */
    KCID_REFUSE_SUSPENDED   /* another id, keycloak_id_reset on, handle suspended: refused */
};

/* The decision for id against a handle whose stored id is stored (NULL for
 * none).  replaced: id is one the handle's binding replaced; reset_on:
 * keycloak_id_reset; suspended: the handle is.  A replaced id is refused
 * first, stored or not: after REBIND * nothing is stored, and the id the
 * handle was cleared of must not be adopted again. */
enum kcid_verdict kcid_decide(const char *stored, int replaced, int reset_on,
                              int suspended, const char *id);

#endif
