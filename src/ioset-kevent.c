/* ioset kqueue()/kevent() backend for srvx
 * Copyright 2008 srvx Development Team
 *
 * This file is part of srvx.
 *
 * srvx is free software; you can redistribute it and/or modify
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

#include "ioset-impl.h"
#include "common.h"
#include "log.h"

#ifdef HAVE_SYS_EVENT_H
# include <sys/event.h>
#endif

#define MAX_EVENTS 16

extern int clock_skew;
static int kq_fd;

static int
ioset_kevent_init(void)
{
    kq_fd = kqueue();
    return kq_fd >= 0;
}

/* The filters registered for an io_fd (fd->engine_bits). */
#define KEV_READ  1
#define KEV_WRITE 2

/* Register (on) or drop (!on) one filter of fd, if it is not so already.
 * Only changes are sent: libkqueue (kqueue on Linux) refuses an EV_ADD of
 * a filter that is already there, which BSD takes as a modify, so
 * re-adding on every update would fail there.  One change per call: when
 * a change fails and kevent() has no room to report it, it returns at
 * once without making the changes after it.  A delete of a filter that
 * is not there (ENOENT) or of a closed descriptor (EBADF) leaves what was
 * wanted, and is not an error. */
static void
ioset_kevent_change(struct io_fd *fd, short filter, int on)
{
    unsigned int bit = (filter == EVFILT_READ) ? KEV_READ : KEV_WRITE;
    struct kevent change;

    if (!on == !(fd->engine_bits & bit))
        return;
    EV_SET(&change, fd->fd, filter, on ? EV_ADD : EV_DELETE, 0, 0, fd);
    if (kevent(kq_fd, &change, 1, NULL, 0, NULL) < 0
        && (on || (errno != ENOENT && errno != EBADF))) {
	log_module(MAIN_LOG, LOG_ERROR, "kevent() %s of the %s filter of fd %d failed: %s",
	           on ? "add" : "delete", (filter == EVFILT_READ) ? "read" : "write", fd->fd, strerror(errno));
        if (on)
            return;             /* not registered */
    }
    if (on)
        fd->engine_bits |= bit;
    else
        fd->engine_bits &= ~bit;
}

static void
ioset_kevent_add(struct io_fd *fd)
{
    ioset_kevent_change(fd, EVFILT_READ, !fd->no_reads);
    ioset_kevent_change(fd, EVFILT_WRITE, fd_wants_writes(fd));
}

/* Dropped even when the descriptor is closed already: BSD dropped them at
 * the close (the deletes answer EBADF), but libkqueue does not see a
 * close, and a filter left behind would make a later EV_ADD for a
 * descriptor that reuses the number fail -- X3 would never hear from
 * that socket. */
static void
ioset_kevent_remove(struct io_fd *fd, UNUSED_ARG(int closed))
{
    ioset_kevent_change(fd, EVFILT_READ, 0);
    ioset_kevent_change(fd, EVFILT_WRITE, 0);
}

static void
ioset_kevent_update(struct io_fd *fd)
{
    ioset_kevent_change(fd, EVFILT_READ, !fd->no_reads);
    ioset_kevent_change(fd, EVFILT_WRITE, fd_wants_writes(fd));
}

static void
ioset_kevent_cleanup(void)
{
    close(kq_fd);
}

static int
ioset_kevent_loop(struct timeval *timeout)
{
    struct kevent events[MAX_EVENTS];
    struct timespec ts;
    struct timespec *pts;
    int is_write;
    int is_read;
    int res;
    int ii;

    /* Try to get events from the kernel. */
    if (timeout) {
	ts.tv_sec = timeout->tv_sec;
	ts.tv_nsec = timeout->tv_usec * 1000;
	pts = &ts;
    } else {
	pts = NULL;
    }
    res = kevent(kq_fd, NULL, 0, events, MAX_EVENTS, pts);
    if ((res < 0) && (errno != EINTR)) {
	log_module(MAIN_LOG, LOG_ERROR, "kevent() poll failed: %s", strerror(errno));
	return 1;
    }
    now = time(NULL) + clock_skew;

    /* Process the events we got.  events[] holds io_fd pointers, and one
     * fd can have both a read and a write entry.  An io_fd closed by an
     * earlier entry stays allocated until ioset_dispatch_end(), and
     * ioset_events() skips it; if its fd number is reused meanwhile, the
     * new io_fd is a new registration whose events come from the next
     * kevent(). */
    ioset_dispatch_begin();
    for (ii = 0; ii < res; ++ii) {
	is_write = events[ii].filter == EVFILT_WRITE;
	is_read = events[ii].filter == EVFILT_READ;
	ioset_events(events[ii].udata, is_read, is_write);
    }
    ioset_dispatch_end();

    return 0;
}

struct io_engine io_engine_kevent = {
    .name = "kevent",
    .init = ioset_kevent_init,
    .add = ioset_kevent_add,
    .remove = ioset_kevent_remove,
    .update = ioset_kevent_update,
    .loop = ioset_kevent_loop,
    .cleanup = ioset_kevent_cleanup,
};
