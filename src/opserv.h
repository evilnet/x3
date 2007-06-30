/* opserv.h - IRC Operator assistant service
 * Copyright 2000-2004 srvx Development Team
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

#ifndef _opserv_h
#define _opserv_h

#define DEFCON_NO_NEW_CHANNELS          1       /* No New Channel Registrations */
#define DEFCON_NO_NEW_NICKS             2       /* No New Nick Registrations */
#define DEFCON_NO_MODE_CHANGE           4       /* No channel MODE changes */
#define DEFCON_FORCE_CHAN_MODES         8       /* Force Chan Mode */
#define DEFCON_REDUCE_SESSION           16      /* Reduce Session Limit */
#define DEFCON_NO_NEW_CLIENTS           32      /* Kill any NEW clients */
#define DEFCON_OPER_ONLY                64      /* Restrict services to oper's only */
#define DEFCON_SILENT_OPER_ONLY         128     /* Silently ignore non-opers */
#define DEFCON_GLINE_NEW_CLIENTS        256     /* Gline any new clients */
#define DEFCON_NO_NEW_MEMOS             512     /* No New Memos Sent */
#define DEFCON_SHUN_NEW_CLIENTS         1024    /* Shun any new clients */

extern int DefCon[6];
extern int checkDefCon(int level);
extern void DefConProcess(struct userNode *user);
extern void defcon_timeout(UNUSED_ARG(void *data));

void init_opserv(const char *nick);
unsigned int gag_create(const char *mask, const char *owner, const char *reason, time_t expires);
int opserv_bad_channel(const char *name);
struct routingPlan* opserv_add_routing_plan(const char *name);
unsigned int opserv_conf_admin_level();
void routing_handle_connect_failure(struct server *source, char *server, char *message);
int activate_routing(struct svccmd *cmd, struct userNode *user, char *plan_name);
void routing_handle_squit(char *server, char* uplink, char *message);
void routing_handle_connect(char *server, char *uplink);
void reroute_timer_reset(unsigned int time);
void routing_init();

#endif
