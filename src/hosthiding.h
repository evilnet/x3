/* hosthiding.h - Host hiding
 * Copyright 2000-2006 X3 Development Team
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

#ifndef _hosthiding_h
#define _hosthiding_h

/*
 * Proto types
 */

extern int str2arr (char **, char *, char *);
extern unsigned long crc32 (const unsigned char *, unsigned int);
extern void make_virthost (char *curr, char *host, char *virt);
extern void make_virtip (char *curr, char *host, char *virt);

/* IPv6 Stuff */
extern void ip62arr (char *, char *);
extern void make_ipv6virthost (char *curr, char *host, char *new);

#endif
