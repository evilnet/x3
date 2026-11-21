/* Standalone asserts for the Keycloak backend pieces; links only the files
 * under test, never the services.  Exit 0 when every assert holds. */
#include "config.h"
#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "kcid.h"

#ifdef WITH_KEYCLOAK
#include <jansson.h>
#include <kc/kc_keycloak.h>
#include "x3kc.h"
#include "x3kc_pure.h"

/* repr after x3kc_repr_set_level(repr, attr, level) equals want; both JSON. */
static int
edit_gives(const char *repr_text, const char *attr, unsigned int level, const char *want_text)
{
    json_t *repr = json_loads(repr_text, 0, NULL);
    json_t *want = json_loads(want_text, 0, NULL);
    int ok;

    assert(repr && want);
    ok = x3kc_repr_set_level(repr, attr, level) == 0 && json_equal(repr, want);
    json_decref(repr);
    json_decref(want);
    return ok;
}

/* x3kc_repr_set_level refuses repr_text (-1) and leaves it as it was. */
static int
edit_refused(const char *repr_text, const char *attr, unsigned int level)
{
    json_t *repr = json_loads(repr_text, JSON_DECODE_ANY, NULL);
    json_t *before = json_loads(repr_text, JSON_DECODE_ANY, NULL);
    int ok;

    assert(repr && before);
    ok = x3kc_repr_set_level(repr, attr, level) == -1 && json_equal(repr, before);
    json_decref(repr);
    json_decref(before);
    return ok;
}

static void
test_seam(void)
{
    char r[X3KC_REASON_MAX + 1], e[X3KC_EMAIL_MAX + 1], big[400], m[128];

    /* The password grant's outcomes (the brief's seven, then the default). */
    assert(x3kc_map_grant(KC_SUCCESS) == X3KC_OK);
    assert(x3kc_map_grant(KC_FORBIDDEN) == X3KC_BAD_PASSWORD);
    assert(x3kc_map_grant(KC_NOT_FOUND) == X3KC_BAD_PASSWORD);
    assert(x3kc_map_grant(KC_DISABLED) == X3KC_DISABLED);
    assert(x3kc_map_grant(KC_UNVERIFIED) == X3KC_NOT_SET_UP);
    assert(x3kc_map_grant(KC_CLIENT_REFUSED) == X3KC_UNREACHABLE);
    assert(x3kc_map_grant(KC_ERROR) == X3KC_UNREACHABLE);
    assert(x3kc_map_grant(KC_TOKEN_ERROR) == X3KC_UNREACHABLE);
    assert(x3kc_map_grant(KC_INVALID_RESPONSE) == X3KC_UNREACHABLE);
    assert(x3kc_map_grant(KC_TIMEOUT) == X3KC_UNREACHABLE);
    assert(x3kc_map_grant(12345) == X3KC_UNREACHABLE);

    /* A write's outcomes. */
    assert(x3kc_map_write(KC_SUCCESS) == X3KC_OK);
    assert(x3kc_map_write(KC_NOT_FOUND) == X3KC_NOT_FOUND);
    assert(x3kc_map_write(KC_FORBIDDEN) == X3KC_REJECTED);
    assert(x3kc_map_write(KC_ERROR) == X3KC_UNREACHABLE);
    assert(x3kc_map_write(KC_TOKEN_ERROR) == X3KC_UNREACHABLE);
    assert(x3kc_map_write(KC_UNAVAILABLE) == X3KC_UNREACHABLE);
    assert(x3kc_map_write(12345) == X3KC_UNREACHABLE);

    /* Slots queued look-ups may fill: the cap less a reserve of
     * max(1, cap / 4) for calls that do not queue, but at least one. */
    assert(x3kc_queue_slots(1) == 1);
    assert(x3kc_queue_slots(2) == 1);
    assert(x3kc_queue_slots(3) == 2);
    assert(x3kc_queue_slots(4) == 3);
    assert(x3kc_queue_slots(8) == 6);
    assert(x3kc_queue_slots(64) == 48);
    assert(x3kc_queue_slots(65) == 49);

    /* reason: control characters out, at most 200 bytes, never a cut
     * UTF-8 character; nothing left is NULL. */
    assert(x3kc_clean_reason(NULL, r) == NULL);
    assert(x3kc_clean_reason("", r) == NULL);
    assert(x3kc_clean_reason("\r\n\t\x01", r) == NULL);
    assert(x3kc_clean_reason("Account is not fully set up", r) == r);
    assert(strcmp(r, "Account is not fully set up") == 0);
    assert(x3kc_clean_reason("a\r\nb\tc\x01" "d\x7f" "e\x1b[31m", r) == r);
    assert(strcmp(r, "abcde[31m") == 0);
    memset(big, 'x', 300);
    big[300] = '\0';
    assert(x3kc_clean_reason(big, r) == r);
    assert(strlen(r) == 200 && strspn(r, "x") == 200);
    memset(big, 'x', 199);
    strcpy(big + 199, "\xc3\xa9tail");                      /* 199 x + "é" */
    assert(x3kc_clean_reason(big, r) == r);
    assert(strlen(r) == 199 && strspn(r, "x") == 199);
    memset(big, 'x', 198);
    strcpy(big + 198, "\xc3\xa9tail");                      /* 198 x + "é" fits */
    assert(x3kc_clean_reason(big, r) == r);
    assert(strlen(r) == 200 && strcmp(r + 198, "\xc3\xa9") == 0);
    memset(big, 'x', 198);
    strcpy(big + 198, "\xe2\x82\xactail");                  /* 198 x + "€" (3 bytes) */
    assert(x3kc_clean_reason(big, r) == r);
    assert(strlen(r) == 198);
    memset(big, '\n', 250);
    strcpy(big + 250, "after");                             /* controls don't count */
    assert(x3kc_clean_reason(big, r) == r);
    assert(strcmp(r, "after") == 0);
    /* '$' is X3's message-code character: doubled, so a reply shows it
     * as it is ("$b" would turn bold, "$N" into a nick) */
    assert(x3kc_clean_reason("costs $5 $b$N$", r) == r);
    assert(strcmp(r, "costs $$5 $$b$$N$$") == 0);
    memset(big, 'x', 199);
    strcpy(big + 199, "$tail");                             /* "$$" does not fit after 199 */
    assert(x3kc_clean_reason(big, r) == r);
    assert(strlen(r) == 199 && strspn(r, "x") == 199);
    memset(big, 'x', 198);
    strcpy(big + 198, "$tail");                             /* "$$" fits exactly */
    assert(x3kc_clean_reason(big, r) == r);
    assert(strlen(r) == 200 && strcmp(r + 198, "$$") == 0);

    /* email: copied as it is or refused (NULL) -- too long, a control
     * character, a space, no '@'. */
    assert(x3kc_clean_email(NULL, e) == NULL);
    assert(x3kc_clean_email("", e) == NULL);
    assert(x3kc_clean_email("user@example.com", e) == e);
    assert(strcmp(e, "user@example.com") == 0);
    assert(x3kc_clean_email("user.example.com", e) == NULL);
    assert(x3kc_clean_email("us er@example.com", e) == NULL);
    assert(x3kc_clean_email("user@example.com\r\n", e) == NULL);
    assert(x3kc_clean_email("user\x01@example.com", e) == NULL);
    assert(x3kc_clean_email("user@example.com\x7f", e) == NULL);
    memset(big, 'a', X3KC_EMAIL_MAX);
    memcpy(big + X3KC_EMAIL_MAX - 12, "@example.com", 12);
    big[X3KC_EMAIL_MAX] = '\0';                             /* exactly the limit */
    assert(x3kc_clean_email(big, e) == e);
    assert(strlen(e) == X3KC_EMAIL_MAX);
    memset(big, 'a', X3KC_EMAIL_MAX + 1);
    memcpy(big + X3KC_EMAIL_MAX + 1 - 12, "@example.com", 12);
    big[X3KC_EMAIL_MAX + 1] = '\0';                         /* one over */
    assert(x3kc_clean_email(big, e) == NULL);

    /* A group id from Keycloak goes into a URL path. */
    assert(x3kc_safe_id("47a960bd-f3c4-4f78-a320-b332eba7eee0") == 1);
    assert(x3kc_safe_id("abc_DEF-123") == 1);
    assert(x3kc_safe_id(NULL) == 0);
    assert(x3kc_safe_id("") == 0);
    assert(x3kc_safe_id("..") == 0);
    assert(x3kc_safe_id("a/b") == 0);
    assert(x3kc_safe_id("a?b") == 0);
    assert(x3kc_safe_id("a%2fb") == 0);
    memset(big, 'a', 65);
    big[65] = '\0';
    assert(x3kc_safe_id(big) == 0);
    big[64] = '\0';
    assert(x3kc_safe_id(big) == 1);

    /* The OpServ level attribute in a user representation: set, replace,
     * remove; every other field and attribute exactly as read. */
#define USER "\"id\":\"u1\",\"username\":\"bob\",\"enabled\":true,\"email\":\"b@x.org\"," \
             "\"requiredActions\":[],\"federationLink\":\"ldap\""
    /* replace */
    assert(edit_gives("{" USER ",\"attributes\":{\"LDAP_ID\":[\"x\"],\"x3_opserv_level\":[\"100\"],\"multi\":[\"1\",\"2\"]}}",
                      "x3_opserv_level", 900,
                      "{" USER ",\"attributes\":{\"LDAP_ID\":[\"x\"],\"x3_opserv_level\":[\"900\"],\"multi\":[\"1\",\"2\"]}}"));
    /* set: the attribute is new */
    assert(edit_gives("{" USER ",\"attributes\":{\"LDAP_ID\":[\"x\"]}}", "x3_opserv_level", 5,
                      "{" USER ",\"attributes\":{\"LDAP_ID\":[\"x\"],\"x3_opserv_level\":[\"5\"]}}"));
    /* set: no attribute map at all, or a null one */
    assert(edit_gives("{" USER "}", "x3_opserv_level", 5,
                      "{" USER ",\"attributes\":{\"x3_opserv_level\":[\"5\"]}}"));
    assert(edit_gives("{" USER ",\"attributes\":null}", "x3_opserv_level", 5,
                      "{" USER ",\"attributes\":{\"x3_opserv_level\":[\"5\"]}}"));
    /* the largest level */
    assert(edit_gives("{" USER "}", "lvl", 4294967295u,
                      "{" USER ",\"attributes\":{\"lvl\":[\"4294967295\"]}}"));
    /* remove at level 0: the key goes, the (now empty) map stays, so the
     * PUT carries the removal */
    assert(edit_gives("{" USER ",\"attributes\":{\"LDAP_ID\":[\"x\"],\"x3_opserv_level\":[\"100\"]}}",
                      "x3_opserv_level", 0,
                      "{" USER ",\"attributes\":{\"LDAP_ID\":[\"x\"]}}"));
    assert(edit_gives("{" USER ",\"attributes\":{\"x3_opserv_level\":[\"100\"]}}", "x3_opserv_level", 0,
                      "{" USER ",\"attributes\":{}}"));
    /* remove: nothing to remove */
    assert(edit_gives("{" USER ",\"attributes\":{\"LDAP_ID\":[\"x\"]}}", "x3_opserv_level", 0,
                      "{" USER ",\"attributes\":{\"LDAP_ID\":[\"x\"]}}"));
    assert(edit_gives("{" USER "}", "x3_opserv_level", 0, "{" USER "}"));
    assert(edit_gives("{" USER ",\"attributes\":null}", "x3_opserv_level", 0,
                      "{" USER ",\"attributes\":null}"));
    /* refused, untouched: not an object; an attribute map that is no map */
    assert(edit_refused("[1,2]", "x3_opserv_level", 5));
    assert(edit_refused("{" USER ",\"attributes\":\"x\"}", "x3_opserv_level", 5));
    assert(edit_refused("{" USER ",\"attributes\":[]}", "x3_opserv_level", 0));
    assert(edit_refused("{" USER "}", "", 5));
    assert(x3kc_repr_set_level(NULL, "x3_opserv_level", 5) == -1);
#undef USER

    /* The hostmask a login-on-connect or SASL request gives a new owner
     * (a Keycloak-id reset with no user yet): what AUTH's reset seeds for
     * a connected user, generate_hostmask(OMITNICK|NO_HIDING|ANY_IDENT). */
    assert(x3kc_loc_mask("bob@host.example.com:192.0.2.7", m, sizeof(m)) == 1);
    assert(strcmp(m, "*@*.example.com") == 0);                 /* two dots: last two labels */
    assert(x3kc_loc_mask("~bob@a.b.c.example.org:192.0.2.7", m, sizeof(m)) == 1);
    assert(strcmp(m, "*@*.c.example.org") == 0);               /* more: last three */
    assert(x3kc_loc_mask("bob@b.c.example.org:192.0.2.7", m, sizeof(m)) == 1);
    assert(strcmp(m, "*@*.c.example.org") == 0);
    assert(x3kc_loc_mask("bob@example.com:192.0.2.7", m, sizeof(m)) == 1);
    assert(strcmp(m, "*@example.com") == 0);                   /* one dot: as it is */
    assert(x3kc_loc_mask("bob@localhost:127.0.0.1", m, sizeof(m)) == 1);
    assert(strcmp(m, "*@localhost") == 0);
    assert(x3kc_loc_mask("bob@172.29.0.1:172.29.0.1", m, sizeof(m)) == 1);
    assert(strcmp(m, "*@172.29.*") == 0);                      /* an address: its /16 */
    assert(x3kc_loc_mask("bob@[2001:db8:1:2::1]:2001:db8:1:2::1", m, sizeof(m)) == 1);
    assert(strcmp(m, "*@2001:db8:1:*") == 0);                  /* IPv6: its /48 */
    assert(x3kc_loc_mask("bob@[::ffff:192.0.2.7]:::ffff:192.0.2.7", m, sizeof(m)) == 1);
    assert(strcmp(m, "*@192.0.*") == 0);                       /* v4-mapped is IPv4 */
    /* not a request's userhost: no mask */
    assert(x3kc_loc_mask(NULL, m, sizeof(m)) == 0);
    assert(x3kc_loc_mask("", m, sizeof(m)) == 0);
    assert(x3kc_loc_mask("bob.example.com:192.0.2.7", m, sizeof(m)) == 0);   /* no '@' */
    assert(x3kc_loc_mask("bob@host.example.com", m, sizeof(m)) == 0);        /* no ip */
    assert(x3kc_loc_mask("bob@:192.0.2.7", m, sizeof(m)) == 0);              /* no host */
    assert(x3kc_loc_mask("bob@[2001:db8::1:2001:db8::1", m, sizeof(m)) == 0); /* no ']' */
    assert(x3kc_loc_mask("bob@host.example.com:192.0.2.7", m, 8) == 0);      /* does not fit */

    /* A password login's answer, for the login paths (AUTH, login-on-connect,
     * SASL PLAIN).  The answers that end an AUTH before X3 looks at the
     * handle, and their replies; OK and a wrong password go on. */
    assert(x3kc_login_reply(X3KC_OK) == NULL);
    assert(x3kc_login_reply(X3KC_BAD_PASSWORD) == NULL);
    assert(strcmp(x3kc_login_reply(X3KC_DISABLED), "NSMSG_KC_DISABLED") == 0);
    assert(strcmp(x3kc_login_reply(X3KC_NOT_SET_UP), "NSMSG_KC_NOT_SET_UP") == 0);
    assert(strcmp(x3kc_login_reply(X3KC_BUSY), "NSMSG_KC_BUSY") == 0);
    assert(strcmp(x3kc_login_reply(X3KC_UNREACHABLE), "NSMSG_KC_FAIL") == 0);
    /* not answers a login gets; still an outage, never a way in */
    assert(strcmp(x3kc_login_reply(X3KC_NOT_FOUND), "NSMSG_KC_FAIL") == 0);
    assert(strcmp(x3kc_login_reply(X3KC_REJECTED), "NSMSG_KC_FAIL") == 0);
    assert(strcmp(x3kc_login_reply((enum x3kc_result)99), "NSMSG_KC_FAIL") == 0);
    /* Only a wrong password counts as a failed password (reply, failpw
     * hooks, auth policer): an outage, a busy seam, X3's own client being
     * refused, a disabled or half-set-up account never do. */
    assert(x3kc_failed_password(X3KC_BAD_PASSWORD) == 1);
    assert(x3kc_failed_password(X3KC_OK) == 0);
    assert(x3kc_failed_password(X3KC_DISABLED) == 0);
    assert(x3kc_failed_password(X3KC_NOT_SET_UP) == 0);
    assert(x3kc_failed_password(X3KC_BUSY) == 0);
    assert(x3kc_failed_password(X3KC_UNREACHABLE) == 0);
    assert(x3kc_failed_password(X3KC_NOT_FOUND) == 0);
    assert(x3kc_failed_password(X3KC_REJECTED) == 0);
}

/* What the answer to a stamp's look-up does (auto-create, Task 7). */
static void
test_stamp_step(void)
{
    const char *A = "a6e4EJ2tEdGAtADAT9QwyA", *B = "BBBBBBBBBBBBBBBBBBBBBB";
    static const enum x3kc_result all[] = {
        X3KC_OK, X3KC_BAD_PASSWORD, X3KC_DISABLED, X3KC_NOT_SET_UP,
        X3KC_NOT_FOUND, X3KC_REJECTED, X3KC_BUSY, X3KC_UNREACHABLE
    };
    unsigned int i;

    /* The user left, or is logged in to X3 by now: nothing, whatever the
     * answer, whatever the handle. */
    for (i = 0; i < sizeof(all) / sizeof(all[0]); i++) {
        assert(x3kc_stamp_step(all[i], 0, 0, "", 0, A, 0) == X3KC_STAMP_DROP);
        assert(x3kc_stamp_step(all[i], 0, 0, A, 0, A, 1) == X3KC_STAMP_DROP);
        assert(x3kc_stamp_step(all[i], 1, 1, "", 0, A, 0) == X3KC_STAMP_DROP);
        assert(x3kc_stamp_step(all[i], 1, 1, A, 0, B, 1) == X3KC_STAMP_DROP);
    }
    /* Keycloak has no such user, and still no handle: unknown. */
    assert(x3kc_stamp_step(X3KC_NOT_FOUND, 1, 0, "", 0, NULL, 0) == X3KC_STAMP_UNKNOWN);
    assert(x3kc_stamp_step(X3KC_NOT_FOUND, 1, 0, A, 0, NULL, 0) == X3KC_STAMP_UNKNOWN);
    /* No answer (outage, deadline, busy) or one a look-up never gets, and
     * still no handle: left for the next event. */
    assert(x3kc_stamp_step(X3KC_UNREACHABLE, 1, 0, "", 0, NULL, 0) == X3KC_STAMP_RETRY_LATER);
    assert(x3kc_stamp_step(X3KC_BUSY, 1, 0, A, 0, NULL, 0) == X3KC_STAMP_RETRY_LATER);
    assert(x3kc_stamp_step(X3KC_REJECTED, 1, 0, "", 0, NULL, 0) == X3KC_STAMP_RETRY_LATER);
    assert(x3kc_stamp_step(X3KC_BAD_PASSWORD, 1, 0, "", 0, NULL, 0) == X3KC_STAMP_RETRY_LATER);
    /* X3KC_OK without an id never counts as a confirmation. */
    assert(x3kc_stamp_step(X3KC_OK, 1, 0, "", 0, NULL, 0) == X3KC_STAMP_RETRY_LATER);
    assert(x3kc_stamp_step(X3KC_OK, 1, 0, "", 0, "", 0) == X3KC_STAMP_RETRY_LATER);
    /* A handle that appeared meanwhile (another confirmed login made it):
     * with no confirmation from this look-up -- none, not found, or OK
     * without an id -- the stamp as it came goes the known-handle way. */
    for (i = 0; i < sizeof(all) / sizeof(all[0]); i++) {
        if (all[i] == X3KC_OK)
            continue;
        assert(x3kc_stamp_step(all[i], 1, 0, "", 0, NULL, 1) == X3KC_STAMP_KNOWN);
        assert(x3kc_stamp_step(all[i], 1, 0, A, 0, NULL, 1) == X3KC_STAMP_KNOWN);
    }
    assert(x3kc_stamp_step(X3KC_OK, 1, 0, "", 0, NULL, 1) == X3KC_STAMP_KNOWN);
    assert(x3kc_stamp_step(X3KC_OK, 1, 0, A, 0, "", 1) == X3KC_STAMP_KNOWN);
    /* An announced id must be the one Keycloak has under that name; a
     * mismatch is ignored even when a handle exists by now (it must not
     * reach the id decision, which could reset that handle). */
    assert(x3kc_stamp_step(X3KC_OK, 1, 0, B, 0, A, 0) == X3KC_STAMP_ID_MISMATCH);
    assert(x3kc_stamp_step(X3KC_OK, 1, 0, B, 0, A, 1) == X3KC_STAMP_ID_MISMATCH);
    /* Confirmed, a handle made meanwhile, an id announced (equal): the
     * known-handle way, with the stamp's own id. */
    assert(x3kc_stamp_step(X3KC_OK, 1, 0, A, 0, A, 1) == X3KC_STAMP_KNOWN);
    /* Confirmed, a handle made meanwhile, no id announced: the looked-up
     * id is compared with the handle's by the caller (never a reset). */
    assert(x3kc_stamp_step(X3KC_OK, 1, 0, "", 0, A, 1) == X3KC_STAMP_BIND_LOOKED_UP);
    assert(x3kc_stamp_step(X3KC_OK, 1, 0, NULL, 0, A, 1) == X3KC_STAMP_BIND_LOOKED_UP);
    /* Confirmed, still no handle: create it. */
    assert(x3kc_stamp_step(X3KC_OK, 1, 0, A, 0, A, 0) == X3KC_STAMP_CREATE);
    assert(x3kc_stamp_step(X3KC_OK, 1, 0, "", 0, A, 0) == X3KC_STAMP_CREATE);
    assert(x3kc_stamp_step(X3KC_OK, 1, 0, NULL, 0, A, 0) == X3KC_STAMP_CREATE);

    /* By its form alone: an announced id, or no timestamp, may create; no
     * id with a timestamp (X3's own name:registered stamp) may not. */
    assert(x3kc_stamp_may_create(A, 0) == 1);
    assert(x3kc_stamp_may_create(A, 1700000000UL) == 1);
    assert(x3kc_stamp_may_create("", 0) == 1);
    assert(x3kc_stamp_may_create(NULL, 0) == 1);
    assert(x3kc_stamp_may_create("", 1700000000UL) == 0);
    assert(x3kc_stamp_may_create(NULL, 1) == 0);
    /* No id, a non-zero timestamp, no handle: never CREATE, whatever
     * Keycloak answered -- not even a confirmation of the name. */
    for (i = 0; i < sizeof(all) / sizeof(all[0]); i++) {
        assert(x3kc_stamp_step(all[i], 1, 0, "", 1700000000UL, all[i] == X3KC_OK ? A : NULL, 0) == X3KC_STAMP_OLD);
        assert(x3kc_stamp_step(all[i], 1, 0, NULL, 1, all[i] == X3KC_OK ? A : NULL, 0) == X3KC_STAMP_OLD);
    }
    /* ... the same stamp with timestamp 0 still creates once confirmed. */
    assert(x3kc_stamp_step(X3KC_OK, 1, 0, "", 0, A, 0) == X3KC_STAMP_CREATE);
    /* ... with an announced id the timestamp does not matter here. */
    assert(x3kc_stamp_step(X3KC_OK, 1, 0, A, 1700000000UL, A, 0) == X3KC_STAMP_CREATE);
    assert(x3kc_stamp_step(X3KC_OK, 1, 0, B, 1700000000UL, A, 0) == X3KC_STAMP_ID_MISMATCH);
    /* A handle that exists by now: the known-handle way (handle_account()
     * checks the timestamp), whatever the timestamp. */
    assert(x3kc_stamp_step(X3KC_UNREACHABLE, 1, 0, "", 1700000000UL, NULL, 1) == X3KC_STAMP_KNOWN);
    assert(x3kc_stamp_step(X3KC_OK, 1, 0, "", 1700000000UL, A, 1) == X3KC_STAMP_BIND_LOOKED_UP);
    /* The user gone or logged in still comes first. */
    assert(x3kc_stamp_step(X3KC_OK, 0, 0, "", 1700000000UL, A, 0) == X3KC_STAMP_DROP);
}
#endif /* WITH_KEYCLOAK */

/* The Keycloak-id decision a login makes once the account name is known to
 * be the Keycloak user's (handle_account for an announced id, AUTH / LOC /
 * SASL PLAIN for the id of a password grant). */
static void
test_kcid_decide(void)
{
    const char *A = "a6e4EJ2tEdGAtADAT9QwyA", *B = "BBBBBBBBBBBBBBBBBBBBBA";
    int kc;

    /* Both modes alike, except for a handle with no id stored. */
    for (kc = 0; kc <= 1; kc++) {
        /* equal: passes, whatever the other inputs */
        assert(kcid_decide(A, 0, 0, 0, kc, A) == KCID_PASS);
        assert(kcid_decide(A, 0, 1, 1, kc, A) == KCID_PASS);
        /* an id the handle's binding replaced: refused, stored or not
         * (after REBIND * nothing is stored, and it must not be bound
         * again) */
        assert(kcid_decide(B, 1, 0, 0, kc, A) == KCID_REFUSE_STALE);
        assert(kcid_decide(B, 1, 1, 0, kc, A) == KCID_REFUSE_STALE);
        assert(kcid_decide(NULL, 1, 0, 0, kc, A) == KCID_REFUSE_STALE);
        assert(kcid_decide(NULL, 1, 1, 1, kc, A) == KCID_REFUSE_STALE);
        /* different: by default refused */
        assert(kcid_decide(B, 0, 0, 0, kc, A) == KCID_REFUSE_MISMATCH);
        assert(kcid_decide(B, 0, 0, 1, kc, A) == KCID_REFUSE_MISMATCH);
        /* different with keycloak_id_reset: reset, unless suspended */
        assert(kcid_decide(B, 0, 1, 0, kc, A) == KCID_RESET);
        assert(kcid_decide(B, 0, 1, 1, kc, A) == KCID_REFUSE_SUSPENDED);
    }
    /* none stored, LDAP or local mode (an announced id): adopted, as on
     * master */
    assert(kcid_decide(NULL, 0, 0, 0, 0, A) == KCID_ADOPT);
    assert(kcid_decide(NULL, 0, 1, 1, 0, A) == KCID_ADOPT);
    /* none stored, Keycloak mode: refused -- the binding script bound
     * every handle it could at the switch, and an oper binds the rest
     * with REBIND */
    assert(kcid_decide(NULL, 0, 0, 0, 1, A) == KCID_REFUSE_UNBOUND);
    assert(kcid_decide(NULL, 0, 1, 0, 1, A) == KCID_REFUSE_UNBOUND);
    assert(kcid_decide(NULL, 0, 1, 1, 1, A) == KCID_REFUSE_UNBOUND);
}

/* An account stamp with no Keycloak id on the wire, for a handle X3 has
 * (handle_account(); user ruling 2026-11-21 23:14). */
static void
test_kcid_decide_no_id(void)
{
    const char *A = "a6e4EJ2tEdGAtADAT9QwyA";
    const unsigned long REG = 1700000000UL;

    /* Keycloak mode, none stored: refused (an ircd's own login with no
     * id -- EXTENDED_ACCOUNTS off, no UUID sub, an impersonated login,
     * AC R with no timestamp -- is not proof that the Keycloak user of
     * that name owns this handle; an oper binds it with REBIND) ... */
    assert(kcid_decide_no_id(NULL, 1, 0, REG) == KCID_REFUSE_UNBOUND);
    assert(kcid_decide_no_id(NULL, 1, REG + 1, REG) == KCID_REFUSE_UNBOUND);
    assert(kcid_decide_no_id(NULL, 1, REG - 1, REG) == KCID_REFUSE_UNBOUND);
    /* ... unless it is X3's own stamp: its timestamp is the handle's
     * registration date (a session X3 logged in, replayed in a burst) */
    assert(kcid_decide_no_id(NULL, 1, REG, REG) == KCID_PASS);
    /* a handle registered at 0 (never in practice): a timestamp of 0 is
     * no timestamp, and is still refused */
    assert(kcid_decide_no_id(NULL, 1, 0, 0) == KCID_REFUSE_UNBOUND);
    /* Keycloak mode, an id stored: fail open, as before */
    assert(kcid_decide_no_id(A, 1, 0, REG) == KCID_PASS);
    assert(kcid_decide_no_id(A, 1, REG, REG) == KCID_PASS);
    assert(kcid_decide_no_id(A, 1, REG + 1, REG) == KCID_PASS);
    /* LDAP or local mode: nothing changes, stored or not */
    assert(kcid_decide_no_id(NULL, 0, 0, REG) == KCID_PASS);
    assert(kcid_decide_no_id(NULL, 0, REG, REG) == KCID_PASS);
    assert(kcid_decide_no_id(NULL, 0, REG + 1, REG) == KCID_PASS);
    assert(kcid_decide_no_id(A, 0, 0, REG) == KCID_PASS);
    assert(kcid_decide_no_id(A, 0, REG, REG) == KCID_PASS);
    assert(kcid_decide_no_id(A, 0, REG + 1, REG) == KCID_PASS);
}

/* The compact form: 22 characters carry 132 bits, the UUID 128, so the
 * last character's low 4 bits are always 0 in the form the ircd and
 * kcid_from_uuid() write.  The decoder refuses any other last character;
 * kcid_canonical() is the one place a non-zero tail is put right. */
static void
test_kcid_forms(void)
{
    char c[23], u[37];

    assert(kcid_from_uuid("6ba7b810-9dad-11d1-80b4-00c04fd430c8", c) == 1);
    assert(strcmp(c, "a6e4EJ2tEdGAtADAT9QwyA") == 0);
    assert(kcid_to_uuid("a6e4EJ2tEdGAtADAT9QwyA", u) == 1);
    assert(strcmp(u, "6ba7b810-9dad-11d1-80b4-00c04fd430c8") == 0);
    assert(kcid_to_uuid("a6e4EJ2tEdGAtADAT9Qwy", u) == 0);     /* 21 chars */
    assert(kcid_to_uuid("a6e4EJ2tEdGAtADAT9QwyAA", u) == 0);   /* 23 chars */
    assert(kcid_to_uuid("a6e4EJ2tEdGAtADAT9Qwy!", u) == 0);    /* bad char */
    assert(kcid_to_uuid("", u) == 0);
    assert(kcid_to_uuid(NULL, u) == 0);
    /* the spare bits: B (1), P (15) and _ (63) set some; Q (16), g (32)
     * and w (48) do not */
    assert(kcid_to_uuid("a6e4EJ2tEdGAtADAT9QwyB", u) == 0);
    assert(kcid_to_uuid("a6e4EJ2tEdGAtADAT9QwyP", u) == 0);
    assert(kcid_to_uuid("a6e4EJ2tEdGAtADAT9Qwy_", u) == 0);
    assert(kcid_to_uuid("a6e4EJ2tEdGAtADAT9QwyQ", u) == 1);
    assert(strcmp(u, "6ba7b810-9dad-11d1-80b4-00c04fd430c9") == 0);
    assert(kcid_to_uuid("a6e4EJ2tEdGAtADAT9Qwyw", u) == 1);
    assert(strcmp(u, "6ba7b810-9dad-11d1-80b4-00c04fd430cb") == 0);
    /* the encoder: either case, dashes or none, one UUID, one form */
    assert(kcid_from_uuid("6BA7B810-9DAD-11D1-80B4-00C04FD430C8", c) == 1);
    assert(strcmp(c, "a6e4EJ2tEdGAtADAT9QwyA") == 0);
    assert(kcid_from_uuid("6ba7b8109dad11d180b400c04fd430c8", c) == 1);
    assert(strcmp(c, "a6e4EJ2tEdGAtADAT9QwyA") == 0);
    assert(kcid_from_uuid("6ba7b810-9dad-11d1-80b4-00c04fd430c8a", c) == 0);
    assert(kcid_from_uuid("6ba7b810-9dad-11d1-80b4-00c04fd430c", c) == 0);
    assert(kcid_from_uuid("6ba7b810-9dad-11d1-80b4-00c04fd430cg", c) == 0);
    assert(kcid_from_uuid(NULL, c) == 0);
    /* a second vector, all bits set, round trip */
    assert(kcid_from_uuid("ffffffff-ffff-ffff-ffff-ffffffffffff", c) == 1);
    assert(strcmp(c, "_____________________w") == 0);
    assert(kcid_to_uuid(c, u) == 1);
    assert(strcmp(u, "ffffffff-ffff-ffff-ffff-ffffffffffff") == 0);
    /* canonical: a non-zero tail is cleared, a canonical id is kept,
     * anything that is no compact id is refused */
    assert(kcid_canonical("a6e4EJ2tEdGAtADAT9QwyB", c) == 1);
    assert(strcmp(c, "a6e4EJ2tEdGAtADAT9QwyA") == 0);
    assert(kcid_canonical("a6e4EJ2tEdGAtADAT9Qwy_", c) == 1);
    assert(strcmp(c, "a6e4EJ2tEdGAtADAT9Qwyw") == 0);
    assert(kcid_canonical("a6e4EJ2tEdGAtADAT9QwyA", c) == 1);
    assert(strcmp(c, "a6e4EJ2tEdGAtADAT9QwyA") == 0);
    assert(kcid_canonical("a6e4EJ2tEdGAtADAT9Qwy", c) == 0);
    assert(kcid_canonical("a6e4EJ2tEdGAtADAT9Qwy!", c) == 0);
    assert(kcid_canonical("6ba7b810-9dad-11d1-80b4-00c04fd430c8", c) == 0);
    assert(kcid_canonical(NULL, c) == 0);
}

/* The oper notices for refused ids: the first at once, then the ones that
 * follow within the minute are held and counted, and the count goes out
 * when the minute is over; a quiet minute starts afresh. */
static void
test_kcid_notice_limit(void)
{
    struct kcid_notice_limit lim = { 0, 0 };

    assert(kcid_notice_take(&lim, 1000) == 1);          /* the first: sent */
    assert(kcid_notice_take(&lim, 1001) == 0);          /* held */
    assert(kcid_notice_take(&lim, 1059) == 0);          /* held */
    assert(kcid_notice_due(&lim) == 1060);              /* when the count goes */
    assert(kcid_notice_flush(&lim, 1060) == 2);         /* two held */
    assert(kcid_notice_due(&lim) == 0);                 /* nothing left */
    /* the flush opened a new minute: still held */
    assert(kcid_notice_take(&lim, 1061) == 0);
    assert(kcid_notice_flush(&lim, 1120) == 1);
    /* a minute with nothing held: the next one goes out at once */
    assert(kcid_notice_take(&lim, 1300) == 1);
    assert(kcid_notice_due(&lim) == 0);                 /* nothing held: no flush due */
}

int main(void)
{
    test_kcid_forms();
    test_kcid_decide();
    test_kcid_decide_no_id();
    test_kcid_notice_limit();
#ifdef WITH_KEYCLOAK
    test_seam();
    test_stamp_step();
    puts("x3kc-test: ok (kcid, seam, stamp)");
#else
    puts("x3kc-test: ok (kcid; built without Keycloak)");
#endif
    return 0;
}
