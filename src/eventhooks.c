/* eventhooks.c - Event hooks
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

#include <assert.h>
#include <stdlib.h>
#include "eventhooks.h"

struct eh_func_list *init_hook_func_list(struct eh_func_list *list, int defpos) {
    if ((defpos != EH_ADD_TAIL) && (defpos != EH_ADD_HEAD))
        list->add_default = EH_ADD_TAIL;
    else
        list->add_default = defpos;
    list->head = NULL;
    list->tail = NULL;
    list->count = 0;
    list->clean = NULL;

    return list;
}

void reg_hook_func_pos(struct eh_func_list *list, eh_func_t func, void *extra, int pos) {
    struct eh_func *newehf = malloc(sizeof(struct eh_func));
    int addpos = pos;

    if ((addpos != EH_ADD_HEAD) && (addpos != EH_ADD_TAIL))
        addpos = list->add_default;

    if (newehf == NULL)
        return;

    newehf->next = NULL;
    newehf->func = func;
    newehf->extra = extra;

    if (list->head == NULL) {
        list->head = newehf;
        list->tail = newehf;
    } else if (addpos > 0) {
        newehf->next = list->head;
        list->head = newehf;
    } else {
        list->tail->next = newehf;
        list->tail = newehf;
    }
    list->count++;
}

void reg_hook_func(struct eh_func_list *list, eh_func_t func, void *extra) {
    reg_hook_func_pos(list, func, extra, EH_ADD_DEFAULT);
}

void unreg_hook_func(struct eh_func_list *list, eh_func_t func, void *extra) {
    struct eh_func *ehfi = list->head;
    struct eh_func *ehfr = NULL;

    if (ehfi != NULL) {
        if ((ehfi->func == func) && (ehfi->extra == extra)) {
            list->head = ehfi->next;
            if (list->tail == ehfi)
                list->tail = NULL;
            if (list->clean != NULL)
                list->clean(ehfi);
            free(ehfi);
            list->count--;
        } else {
            for (ehfi=list->head; ehfi!=NULL; ehfi=ehfi->next) {
                if (ehfi->next != NULL) {
                    if ((ehfi->next->func == func) && (ehfi->next->extra == extra)) {
                        ehfr = ehfi->next;
                        ehfi->next = ehfi->next->next;
                        if (list->tail == ehfr)
                            list->tail = ehfi;
                        if (list->clean != NULL)
                            list->clean(ehfr);
                        free(ehfr);
                        list->count--;
                        break;
                    }
                }
            }
        }
    }
}

void free_hook_func_list(struct eh_func_list *list) {
    struct eh_func *ehfi = NULL;
    struct eh_func *ehfn = NULL;
    int i = 0;

    if (list->head == NULL)
        return;

    for (ehfi=list->head; ehfi!=NULL; ehfi=ehfn) {
        ehfn = ehfi->next;

        if (list->clean != NULL)
            list->clean(ehfi);

        free(ehfi);
        i++;
    }

    assert(i==list->count);

    list->head = NULL;
    list->tail = NULL;
    list->count = 0;
}

void call_hook_func_args(struct eh_func_list *list, void *callextra) {
	struct eh_func *ehfi = NULL;

	for (ehfi=list->head; ehfi!=NULL; ehfi=ehfi->next) {
		if (ehfi->func(ehfi->extra, callextra) != EH_CONT)
			break;
	}
}

void call_hook_func_noargs(struct eh_func_list *list) {
	call_hook_func_args(list, NULL);
}
