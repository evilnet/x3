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
    char r[X3KC_REASON_MAX + 1], e[X3KC_EMAIL_MAX + 1], big[400];

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
}
#endif /* WITH_KEYCLOAK */

int main(void)
{
    char c[23], u[37];
    assert(kcid_from_uuid("6ba7b810-9dad-11d1-80b4-00c04fd430c8", c) == 1);
    assert(strcmp(c, "a6e4EJ2tEdGAtADAT9QwyA") == 0);
    assert(kcid_to_uuid("a6e4EJ2tEdGAtADAT9QwyA", u) == 1);
    assert(strcmp(u, "6ba7b810-9dad-11d1-80b4-00c04fd430c8") == 0);
    assert(kcid_to_uuid("a6e4EJ2tEdGAtADAT9Qwy", u) == 0);     /* 21 chars */
    assert(kcid_to_uuid("a6e4EJ2tEdGAtADAT9Qwy!", u) == 0);    /* bad char */
    assert(kcid_to_uuid(NULL, u) == 0);
#ifdef WITH_KEYCLOAK
    test_seam();
    puts("x3kc-test: ok (kcid, seam)");
#else
    puts("x3kc-test: ok (kcid; built without Keycloak)");
#endif
    return 0;
}
