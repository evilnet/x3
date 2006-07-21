/* opserv.h - IRC Operator assistant service
 * Copyright 2000-2004 srvx Development Team
 *
 * This file is part of x3.
 *
 * x3 is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
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

#ifndef _opserv_h
#define _opserv_h

void init_opserv(const char *nick);
unsigned int gag_create(const char *mask, const char *owner, const char *reason, time_t expires);
int opserv_bad_channel(const char *name);
struct routingPlan* opserv_add_routing_plan(const char *name);
unsigned int opserv_conf_admin_level();
void routing_handle_connect_failure(struct server *source, char *server, char *message);
int activate_routing(struct svccmd *cmd, struct userNode *user, char *plan_name);
void routing_handle_squit(char *server, char* uplink, char *message);
void routing_handle_connect(char *server, char *uplink);

#endif
