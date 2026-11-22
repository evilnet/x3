#include <string.h>
#include "kcid.h"

/* 16 UUID bytes <-> 22 unpadded base64url chars.  Mirrors nefarious's
 * account_id, the form the ircd announces and saxdb stores. */
static const char kcid_b64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

int
kcid_from_uuid(const char *uuid, char out[23])
{
    unsigned char raw[16];
    int digits = 0, hi = -1, i, o = 0;
    const char *p;

    if (!uuid)
        return 0;
    for (p = uuid; *p; p++) {
        int v;
        if (*p == '-')
            continue;
        if (*p >= '0' && *p <= '9') v = *p - '0';
        else if (*p >= 'a' && *p <= 'f') v = *p - 'a' + 10;
        else if (*p >= 'A' && *p <= 'F') v = *p - 'A' + 10;
        else return 0;
        if (digits == 32)
            return 0;
        if (hi < 0) hi = v; else { raw[digits/2] = (hi << 4) | v; hi = -1; }
        digits++;
    }
    if (digits != 32)
        return 0;
    for (i = 0; i < 16; i += 3) {                 /* last group is 16%3==1 byte */
        unsigned int n = raw[i] << 16;
        int bytes = 1;
        if (i + 1 < 16) { n |= raw[i+1] << 8; bytes = 2; }
        if (i + 2 < 16) { n |= raw[i+2];      bytes = 3; }
        out[o++] = kcid_b64[(n >> 18) & 63];
        out[o++] = kcid_b64[(n >> 12) & 63];
        if (bytes > 1) out[o++] = kcid_b64[(n >> 6) & 63];
        if (bytes > 2) out[o++] = kcid_b64[n & 63];
    }
    out[o] = 0;
    return o == 22;
}

int
kcid_to_uuid(const char *compact, char out[37])
{
    static const char hex[] = "0123456789abcdef";
    unsigned char raw[18];
    int vals[22], i, o = 0;

    if (!compact || strlen(compact) != 22)
        return 0;
    for (i = 0; i < 22; i++) {
        const char *at = strchr(kcid_b64, compact[i]);
        if (!compact[i] || !at)
            return 0;
        vals[i] = (int)(at - kcid_b64);
    }
    /* 22 chars carry 132 bits; the last char's low 4 bits are padding.
     * Only 0 is accepted there (the form the ircd and kcid_from_uuid()
     * write), so one user has one compact id. */
    if (vals[21] & 15)
        return 0;
    for (i = 0; i < 22; i += 4) {
        unsigned int n = (vals[i] << 18) | (vals[i+1] << 12);
        if (i + 2 < 22) n |= vals[i+2] << 6;
        if (i + 3 < 22) n |= vals[i+3];
        raw[o++] = (n >> 16) & 255;
        raw[o++] = (n >> 8) & 255;
        raw[o++] = n & 255;
    }
    for (i = 0, o = 0; i < 16; i++) {
        if (i == 4 || i == 6 || i == 8 || i == 10)
            out[o++] = '-';
        out[o++] = hex[raw[i] >> 4];
        out[o++] = hex[raw[i] & 15];
    }
    out[o] = 0;
    return 1;
}

int
kcid_canonical(const char *compact, char out[23])
{
    const char *at;
    int i;

    if (!compact || strlen(compact) != 22)
        return 0;
    for (i = 0; i < 22; i++)
        if (!compact[i] || !strchr(kcid_b64, compact[i]))
            return 0;
    memcpy(out, compact, 22);
    at = strchr(kcid_b64, compact[21]);
    out[21] = kcid_b64[(at - kcid_b64) & ~15];
    out[22] = 0;
    return 1;
}

enum kcid_verdict
kcid_decide(const char *stored, int replaced, int reset_on, int suspended,
            int keycloak_mode, const char *id)
{
    if (replaced)
        return KCID_REFUSE_STALE;
    if (!stored)
        return keycloak_mode ? KCID_REFUSE_UNBOUND : KCID_ADOPT;
    if (!strcmp(stored, id))
        return KCID_PASS;
    if (reset_on && suspended)
        return KCID_REFUSE_SUSPENDED;
    if (reset_on)
        return KCID_RESET;
    return KCID_REFUSE_MISMATCH;
}

enum kcid_verdict
kcid_decide_no_id(const char *stored, int keycloak_mode, unsigned long stamp_ts,
                  unsigned long registered)
{
    if (!keycloak_mode || stored)
        return KCID_PASS;
    if (stamp_ts && stamp_ts == registered)
        return KCID_PASS;
    return KCID_REFUSE_UNBOUND;
}

int
kcid_notice_take(struct kcid_notice_limit *lim, long now)
{
    if (lim->window_start && now < lim->window_start + KCID_NOTICE_WINDOW) {
        lim->held++;
        return 0;
    }
    lim->window_start = now;
    lim->held = 0;
    return 1;
}

long
kcid_notice_due(const struct kcid_notice_limit *lim)
{
    return lim->held ? lim->window_start + KCID_NOTICE_WINDOW : 0;
}

unsigned int
kcid_notice_flush(struct kcid_notice_limit *lim, long now)
{
    unsigned int held = lim->held;

    lim->held = 0;
    /* A count going out opens the next minute; none lets the next notice
     * out at once. */
    lim->window_start = held ? now : 0;
    return held;
}
