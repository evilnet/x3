/* x3kc.h - X3's Keycloak backend
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

#ifndef X3KC_H
#define X3KC_H

/* Brings the Keycloak client in line with the nickserv block's keycloak_*
 * settings, which nickserv_conf_read() has just read and checked.  Called
 * at the end of every nickserv_conf_read() and from init_nickserv(); a
 * call that finds nothing changed does nothing.  With keycloak_refused set
 * it leaves Keycloak unconfigured (every call answered X3KC_UNREACHABLE). */
void x3kc_configure(void);

/* 1 if the libcurl X3 runs with resolves names without blocking
 * (CURL_VERSION_ASYNCHDNS: the threaded resolver or c-ares).  Without it a
 * slow or unanswered DNS look-up for the Keycloak host would stall all of
 * X3 for as long as the look-up takes, so Keycloak mode is refused.
 * *version: libcurl's version string, for the log. */
int x3kc_async_dns(const char **version);

#endif /* X3KC_H */
