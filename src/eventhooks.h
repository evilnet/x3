/* eventhooks.h - Event hooks
 * Copyright 2000-2024 Evilnet Development
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

#ifndef INCLUDED_eventhooks_h
#define INCLUDED_eventhooks_h

#define EH_ADD_HEAD     1
#define EH_ADD_TAIL     -1
#define EH_ADD_DEFAULT  0

#define DEFINE_EH_FUNC_LIST(l, d, cf) struct eh_func_list l = {NULL, NULL, d, 0, cf}
#define INIT_EH_FUNC_LIST(d) {NULL, NULL, d, 0}

#define EH_CONT			0
#define EH_STOP			1

struct eh_func;

typedef int (*eh_func_t) (void *extra, void *callextra);
typedef void (*eh_clean_func_t) (struct eh_func *ehf);

struct eh_func {
    struct eh_func *next;
    eh_func_t func;
    void *extra;
};

struct eh_func_list {
    struct eh_func *head;
    struct eh_func *tail;
    int add_default;
    int count;
    eh_clean_func_t clean;
};

struct eh_func_list *init_hook_func_list(struct eh_func_list *list, int defpos);
void reg_hook_func(struct eh_func_list *list, eh_func_t func, void *extra);
void reg_hook_func_pos(struct eh_func_list *list, eh_func_t func, void *extra, int pos);
void unreg_hook_func(struct eh_func_list *list, eh_func_t func, void *extra);
void free_hook_func_list(struct eh_func_list *list);
void call_hook_func_noargs(struct eh_func_list *list);
void call_hook_func_args(struct eh_func_list *list, void *callextra);

#endif /* INCLUDED_eventhooks_h */
