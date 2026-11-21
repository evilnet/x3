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
        if (n == X3KC_REASON_MAX) {
            truncated = 1;
            break;
        }
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

#else /* !WITH_KEYCLOAK */

/* ISO C wants something in a translation unit. */
typedef int x3kc_pure_not_built;

#endif /* WITH_KEYCLOAK */
