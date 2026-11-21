/* x3_kc_adapter.h - runs the Keycloak client (src/kc/) on X3's event loop
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
 */

#ifndef X3_KC_ADAPTER_H
#define X3_KC_ADAPTER_H

#include <kc/kc_event.h>
#include <kc/kc_log.h>

/* Registers the "keycloak" log type and the adapter's idle function (its
 * millisecond timers).  Call once ioset and logging are up, before
 * kc_init(); a second call does nothing. */
void x3_kc_adapter_init(void);

/* The ops to hand to kc_init(). */
const struct kc_event_ops *x3_kc_get_event_ops(void);
const struct kc_log_ops *x3_kc_get_log_ops(void);

/* Drops every socket registration and timer the adapter still holds and
 * unregisters the idle function.  Call after kc_shutdown(), at exit. */
void x3_kc_adapter_cleanup(void);

#endif /* X3_KC_ADAPTER_H */
