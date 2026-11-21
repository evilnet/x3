/* x3kc_pure.c - the pure pieces of X3's Keycloak seam (x3kc.c)
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
 * No X3 headers: x3kc-test links this file alone.  Its contents exist only
 * with WITH_KEYCLOAK (x3kc-test is built either way).
 */

#include "config.h"

#ifdef WITH_KEYCLOAK

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include <kc/kc_keycloak.h>
#include "x3kc_pure.h"

enum x3kc_result
x3kc_map_grant(int kc_result)
{
    switch (kc_result) {
    case KC_SUCCESS:
        return X3KC_OK;
    case KC_FORBIDDEN:
    case KC_NOT_FOUND:
        return X3KC_BAD_PASSWORD;
    case KC_DISABLED:
        return X3KC_DISABLED;
    case KC_UNVERIFIED:
        return X3KC_NOT_SET_UP;
    case KC_CLIENT_REFUSED:     /* X3's own client: logged by the caller */
    default:
        return X3KC_UNREACHABLE;
    }
}

const char *
x3kc_login_reply(enum x3kc_result res)
{
    switch (res) {
    case X3KC_OK:
    case X3KC_BAD_PASSWORD:
        return NULL;
    case X3KC_DISABLED:
        return "NSMSG_KC_DISABLED";
    case X3KC_NOT_SET_UP:
        return "NSMSG_KC_NOT_SET_UP";
    case X3KC_BUSY:
        return "NSMSG_KC_BUSY";
    case X3KC_UNREACHABLE:
    default:
        return "NSMSG_KC_FAIL";
    }
}

int
x3kc_failed_password(enum x3kc_result res)
{
    return res == X3KC_BAD_PASSWORD;
}

enum x3kc_result
x3kc_map_write(int kc_result)
{
    switch (kc_result) {
    case KC_SUCCESS:
        return X3KC_OK;
    case KC_NOT_FOUND:
        return X3KC_NOT_FOUND;
    case KC_FORBIDDEN:
        return X3KC_REJECTED;
    default:
        return X3KC_UNREACHABLE;
    }
}

unsigned int
x3kc_queue_slots(unsigned int max_pending)
{
    unsigned int reserve = max_pending / 4;

    if (max_pending == 0)
        return 0;
    if (reserve < 1)
        reserve = 1;
    return max_pending > reserve + 1 ? max_pending - reserve : 1;
}

enum x3kc_queue_pick
x3kc_queue_next(int lookups_waiting, int deletes_waiting, int share_full)
{
    if (share_full)
        return X3KC_QUEUE_NONE;
    if (lookups_waiting)
        return X3KC_QUEUE_LOOKUP;
    if (deletes_waiting)
        return X3KC_QUEUE_DELETE;
    return X3KC_QUEUE_NONE;
}

int
x3kc_queue_must_wait(int is_delete, int lookups_waiting, int deletes_waiting, int share_full)
{
    if (share_full || lookups_waiting)
        return 1;
    return is_delete && deletes_waiting;
}

int
x3kc_loc_mask(const char *userhost, char *out, size_t outlen)
{
    const char *at, *host, *hend, *ip;
    char hostbuf[256], ipbuf[64], gen[256 + 4];
    unsigned char a[16];
    size_t hlen;
    int n, dots, i;

    if (!userhost || !(at = strchr(userhost, '@')))
        return 0;
    host = at + 1;
    if (*host == '[') {
        host++;
        if (!(hend = strchr(host, ']')) || hend[1] != ':')
            return 0;
        ip = hend + 2;
    } else {
        if (!(hend = strchr(host, ':')))
            return 0;
        ip = hend + 1;
    }
    hlen = hend - host;
    if (!hlen || hlen >= sizeof(hostbuf) || !*ip || strlen(ip) >= sizeof(ipbuf))
        return 0;
    memcpy(hostbuf, host, hlen);
    hostbuf[hlen] = '\0';
    strcpy(ipbuf, ip);

    if (inet_pton(AF_INET, hostbuf, a) == 1 || inet_pton(AF_INET6, hostbuf, a) == 1) {
        /* The host is an address: the mask is the connection address's
         * /16 (IPv4, also v4-mapped) or /48 (IPv6). */
        static const unsigned char v4mapped[12] = { 0,0,0,0, 0,0,0,0, 0,0,0xff,0xff };

        if (inet_pton(AF_INET, ipbuf, a) == 1)
            snprintf(gen, sizeof(gen), "%d.%d.*", a[0], a[1]);
        else if (inet_pton(AF_INET6, ipbuf, a) == 1 && !memcmp(a, v4mapped, 12))
            snprintf(gen, sizeof(gen), "%d.%d.*", a[12], a[13]);
        else if (inet_pton(AF_INET6, ipbuf, a) == 1)
            snprintf(gen, sizeof(gen), "%x:%x:%x:*", (a[0] << 8) | a[1], (a[2] << 8) | a[3], (a[4] << 8) | a[5]);
        else
            snprintf(gen, sizeof(gen), "%s", ipbuf);
    } else {
        /* A name: one or two labels as it is; three, the last two; more,
         * the last three. */
        for (i = dots = 0; hostbuf[i]; i++)
            if (hostbuf[i] == '.')
                dots++;
        if (dots < 2) {
            snprintf(gen, sizeof(gen), "%s", hostbuf);
        } else {
            int keep = dots == 2 ? 2 : 3, seen = 0;

            for (i = (int)hlen - 1; i >= 0; i--)
                if (hostbuf[i] == '.' && ++seen == keep)
                    break;
            snprintf(gen, sizeof(gen), "*.%s", hostbuf + i + 1);
        }
    }
    n = snprintf(out, outlen, "*@%s", gen);
    return n > 0 && (size_t)n < outlen;
}

static int
is_control(unsigned char c)
{
    return c < 0x20 || c == 0x7f;
}

const char *
x3kc_clean_reason(const char *in, char out[X3KC_REASON_MAX + 1])
{
    const unsigned char *p;
    size_t n = 0;
    int truncated = 0;

    if (!in)
        return NULL;
    for (p = (const unsigned char *)in; *p; p++) {
        if (is_control(*p))
            continue;
        /* '$' starts an X3 message code when the reason goes into a
         * reply: doubled, it shows as itself.  The pair is never cut. */
        if (n + (*p == '$' ? 2 : 1) > X3KC_REASON_MAX) {
            truncated = 1;
            break;
        }
        if (*p == '$')
            out[n++] = '$';
        out[n++] = (char)*p;
    }
    if (truncated && n > 0) {
        /* Never end in part of a UTF-8 character: find where the last
         * character starts and drop it if not all of its bytes made it. */
        size_t start = n;
        unsigned char lead;
        size_t want;

        while (start > 0 && start > n - 4
               && ((unsigned char)out[start - 1] & 0xc0) == 0x80)
            start--;
        if (start > 0) {
            lead = (unsigned char)out[start - 1];
            if (lead >= 0xc0) {
                start--;
                want = lead >= 0xf0 ? 4 : lead >= 0xe0 ? 3 : 2;
                if (n - start < want)
                    n = start;
            }
        }
    }
    out[n] = '\0';
    return n ? out : NULL;
}

const char *
x3kc_clean_email(const char *in, char out[X3KC_EMAIL_MAX + 1])
{
    const unsigned char *p;
    size_t len;

    if (!in)
        return NULL;
    len = strlen(in);
    if (len == 0 || len > X3KC_EMAIL_MAX || !strchr(in, '@'))
        return NULL;
    for (p = (const unsigned char *)in; *p; p++)
        if (is_control(*p) || *p == ' ')
            return NULL;
    memcpy(out, in, len + 1);
    return out;
}

int
x3kc_safe_id(const char *id)
{
    size_t n;

    if (!id)
        return 0;
    for (n = 0; id[n]; n++) {
        char c = id[n];
        if (n == 64)
            return 0;
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
              || (c >= '0' && c <= '9') || c == '-' || c == '_'))
            return 0;
    }
    return n > 0;
}

int
x3kc_repr_set_level(json_t *repr, const char *attr, unsigned int level)
{
    json_t *attrs, *values, *fresh = NULL;
    char text[16];

    if (!json_is_object(repr) || !attr || !*attr)
        return -1;
    attrs = json_object_get(repr, "attributes");
    if (attrs && !json_is_object(attrs) && !json_is_null(attrs))
        return -1;

    if (level == 0) {
        /* Nothing to remove from an absent or null map. */
        if (json_is_object(attrs))
            json_object_del(attrs, attr);
        return 0;
    }

    snprintf(text, sizeof(text), "%u", level);
    values = json_array();
    if (!values || json_array_append_new(values, json_string(text)) != 0) {
        json_decref(values);
        return -1;
    }
    if (!json_is_object(attrs)) {
        fresh = json_object();
        if (!fresh) {
            json_decref(values);
            return -1;
        }
        attrs = fresh;
    }
    /* json_object_set_new() takes values in every case. */
    if (json_object_set_new(attrs, attr, values) != 0) {
        json_decref(fresh);
        return -1;
    }
    if (fresh && json_object_set_new(repr, "attributes", fresh) != 0)
        return -1;      /* fresh is released; repr is as it was */
    return 0;
}

int
x3kc_stamp_may_create(const char *announced_id, unsigned long timestamp)
{
    return (announced_id && *announced_id) || timestamp == 0;
}

enum x3kc_stamp_step
x3kc_stamp_step(enum x3kc_result res, int user_present, int user_authed,
                const char *announced_id, unsigned long timestamp,
                const char *found_id, int handle_exists)
{
    int confirmed = res == X3KC_OK && found_id && *found_id;
    int announced = announced_id && *announced_id;

    if (!user_present || user_authed)
        return X3KC_STAMP_DROP;
    if (confirmed && announced && strcmp(announced_id, found_id))
        return X3KC_STAMP_ID_MISMATCH;
    if (handle_exists)
        return (confirmed && !announced) ? X3KC_STAMP_BIND_LOOKED_UP : X3KC_STAMP_KNOWN;
    if (!x3kc_stamp_may_create(announced_id, timestamp))
        return X3KC_STAMP_OLD;
    if (res == X3KC_NOT_FOUND)
        return X3KC_STAMP_UNKNOWN;
    if (!confirmed)
        return X3KC_STAMP_RETRY_LATER;
    return X3KC_STAMP_CREATE;
}

#else /* !WITH_KEYCLOAK */

/* ISO C wants something in a translation unit. */
typedef int x3kc_pure_not_built;

#endif /* WITH_KEYCLOAK */
