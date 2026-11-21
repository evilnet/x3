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
    /* 22 chars carry 132 bits; the last char's low 4 bits are padding and
     * are dropped, so the 22 characters are accepted as-is. */
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

enum kcid_verdict
kcid_decide(const char *stored, int replaced, int reset_on, int suspended, const char *id)
{
    if (replaced)
        return KCID_REFUSE_STALE;
    if (!stored)
        return KCID_ADOPT;
    if (!strcmp(stored, id))
        return KCID_PASS;
    if (reset_on && suspended)
        return KCID_REFUSE_SUSPENDED;
    if (reset_on)
        return KCID_RESET;
    return KCID_REFUSE_MISMATCH;
}
