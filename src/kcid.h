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

#endif
