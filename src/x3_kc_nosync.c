/* x3_kc_nosync.c - X3's stand-in for the kc client's blocking HTTP call
 *
 * This file is part of x3.
 *
 * x3 is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * The vendored kc client (src/kc/, see src/kc/SOURCE) is copied from the
 * ircd without its blocking HTTP client, kc_http_sync.c: X3 must never
 * block its main loop on Keycloak.  kc_jwt.c still names one symbol of
 * that client, kc_http_sync_perform(), in its JWKS fetch, which only
 * kc_jwt_validate_local() and kc_jwt_prime_cache() reach.  X3 calls
 * neither.  This definition satisfies the link, touches no network, says
 * so in the log, and answers "nothing received".
 *
 * Built only with WITH_KEYCLOAK (configure adds it to MODULE_OBJS).
 */

#include "log.h"

#include <stdlib.h>
#include <kc/kc_http_sync.h>

long
kc_http_sync_perform(struct kc_http_sync_opts opts,
                     struct kc_http_sync_mem *chunk_out)
{
    log_module(MAIN_LOG, LOG_ERROR,
               "kc: blocking HTTP request %s (%s) refused: X3 has no blocking HTTP client and this path must not be reached",
               opts.request_id ? opts.request_id : "-",
               opts.uri ? opts.uri : "-");
    /* The header's failure contract: response freed and NULL.  kc buffers
     * come from libc malloc, so "(free)" keeps common.h's debug-allocator
     * free() macro (--with-malloc=x3/slab/boehm-gc) out of it. */
    if (chunk_out) {
        (free)(chunk_out->response);
        chunk_out->response = NULL;
        chunk_out->size = 0;
    }
    return 0;
}
