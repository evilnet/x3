/* x3kc.c - X3's Keycloak backend
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
 * Built only with WITH_KEYCLOAK (configure adds it to MODULE_OBJS).
 */

#include "common.h"
#include "log.h"
#include "nickserv.h"
#include "x3_kc_adapter.h"
#include "x3kc.h"

#include <curl/curl.h>
#include <kc/kc.h>
#include <kc/kc_keycloak.h>

#include <stdlib.h>
#include <string.h>

extern struct nickserv_config nickserv_conf;

static struct log_type *KC_LOG;

/* kc_init() has run: libcurl's multi handle exists, on the adapter. */
static int kc_running;
/* kc_keycloak_init() has run and kc_keycloak_shutdown() has not since. */
static int kc_configured;

/* What kc_keycloak_init() was last given.  Copies: the strings in
 * nickserv_conf point into the config database, which a rehash replaces
 * before nickserv_conf_read() runs again. */
static char *applied_url;
static char *applied_realm;
static char *applied_client_id;
static char *applied_secret;
static unsigned int applied_timeout;

static void
x3kc_forget_applied(void)
{
    free(applied_url);
    free(applied_realm);
    free(applied_client_id);
    free(applied_secret);
    applied_url = applied_realm = applied_client_id = applied_secret = NULL;
    applied_timeout = 0;
}

static int
x3kc_differs(const char *applied, const char *wanted)
{
    return !applied || strcmp(applied, wanted) != 0;
}

/* Process exit only.  kc_shutdown() drops the transfers in flight without
 * calling them back, which is right here and nowhere else. */
static void
x3kc_exit(UNUSED_ARG(void *extra))
{
    if (kc_configured)
        kc_keycloak_shutdown();
    kc_configured = 0;
    kc_shutdown();
    kc_running = 0;
    x3_kc_adapter_cleanup();
    x3kc_forget_applied();
}

int
x3kc_async_dns(const char **version)
{
    const curl_version_info_data *info = curl_version_info(CURLVERSION_NOW);

    *version = info && info->version ? info->version : "unknown version";
    return info && (info->features & CURL_VERSION_ASYNCHDNS) ? 1 : 0;
}

void
x3kc_configure(void)
{
    const struct nickserv_config *conf = &nickserv_conf;
    struct kc_config cfg;
    int restart;

    if (!conf->keycloak_enable || conf->keycloak_refused) {
        /* Turned off by a rehash, or a rehash's settings were refused:
         * drop the configuration (see below for what happens to requests
         * in flight).  Never started: nothing of kc is touched, so no
         * libcurl handle and no keycloak log.  Refused: every call is
         * answered X3KC_UNREACHABLE (kc_configured is 0) until a rehash
         * brings settings nickserv_conf_read() accepts. */
        if (kc_configured) {
            kc_keycloak_shutdown();
            kc_configured = 0;
            x3kc_forget_applied();
            if (conf->keycloak_enable)
                log_module(KC_LOG, LOG_ERROR, "Keycloak logins stopped: the rehashed keycloak_* settings were refused; logins answer that the account server cannot be reached until a rehash with settings X3 accepts.");
            else
                log_module(KC_LOG, LOG_INFO, "Keycloak logins off (keycloak_enable 0).");
        }
        return;
    }

    if (!kc_running) {
        x3_kc_adapter_init();
        KC_LOG = log_register_type("keycloak", NULL);
        if (kc_init(x3_kc_get_event_ops(), x3_kc_get_log_ops()) != 0) {
            log_module(KC_LOG, LOG_ERROR, "Unable to start the Keycloak client; Keycloak logins will fail until a rehash starts it.");
            return;
        }
        kc_running = 1;
        reg_exit_func(x3kc_exit, NULL);
    }

    if (kc_configured
        && !x3kc_differs(applied_url, conf->keycloak_url)
        && !x3kc_differs(applied_realm, conf->keycloak_realm)
        && !x3kc_differs(applied_client_id, conf->keycloak_client_id)
        && !x3kc_differs(applied_secret, conf->keycloak_client_secret)
        && applied_timeout == conf->keycloak_timeout)
        return;

    /* A setting kc uses changed.  kc_keycloak_shutdown() answers the
     * operations still queued for an admin token at once (KC_TOKEN_ERROR),
     * drops the cached token, and does NOT cancel requests already in
     * flight: each of those still calls back later, exactly once, with the
     * old configuration's result, so whatever their callbacks point at
     * must outlive this.  The HTTP layer (kc_shutdown()) is left running
     * on purpose: it would drop those transfers without ever calling them
     * back.  It is shut down only at process exit (x3kc_exit()). */
    restart = kc_configured;
    if (kc_configured) {
        kc_keycloak_shutdown();
        kc_configured = 0;
    }
    x3kc_forget_applied();

    memset(&cfg, 0, sizeof(cfg));
    cfg.base_url = conf->keycloak_url;
    cfg.realm = conf->keycloak_realm;
    cfg.client_id = conf->keycloak_client_id;
    cfg.client_secret = conf->keycloak_client_secret;
    cfg.timeout_ms = (long)conf->keycloak_timeout;
    if (kc_keycloak_init(&cfg) != 0) {
        log_module(KC_LOG, LOG_ERROR, "Unable to configure the Keycloak client for %s/realms/%s; Keycloak logins will fail until a rehash.", conf->keycloak_url, conf->keycloak_realm);
        return;
    }
    kc_configured = 1;
    applied_url = strdup(conf->keycloak_url);
    applied_realm = strdup(conf->keycloak_realm);
    applied_client_id = strdup(conf->keycloak_client_id);
    applied_secret = strdup(conf->keycloak_client_secret);
    applied_timeout = conf->keycloak_timeout;

    /* Never the secret. */
    log_module(KC_LOG, LOG_INFO, "Keycloak logins %s: realm %s/realms/%s, client %s, timeout %u ms.",
               restart ? "reconfigured" : "on", conf->keycloak_url, conf->keycloak_realm,
               conf->keycloak_client_id, conf->keycloak_timeout);
}
