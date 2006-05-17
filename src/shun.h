/* shun.h - Shun database
 * Copyright 2001-2004 srvx Development Team
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

#ifndef SHUN_H
#define SHUN_H

#include "hash.h"

struct shun {
    time_t issued;
    time_t expires;
    char *issuer;
    char *target;
    char *reason;
};

struct shun_discrim {
    unsigned int limit;
    enum { SSUBSET, SEXACT, SSUPERSET } target_mask_type;
    char *issuer_mask;
    char *target_mask;
    char *alt_target_mask;
    char *reason_mask;
    time_t max_issued;
    time_t min_expire;
};

void shun_init(void);
struct shun *shun_add(const char *issuer, const char *target, unsigned long duration, const char *reason, time_t issued, int announce);
struct shun *shun_find(const char *target);
int shun_remove(const char *target, int announce);
void shun_refresh_server(struct server *srv);
void shun_refresh_all(void);
unsigned int shun_count(void);

typedef void (*shun_search_func)(struct shun *shun, void *extra);
struct shun_discrim *shun_discrim_create(struct userNode *user, struct userNode *src, unsigned int argc, char *argv[]);
unsigned int shun_discrim_search(struct shun_discrim *discrim, shun_search_func gsf, void *data);

#endif /* !defined(SHUN_H) */
