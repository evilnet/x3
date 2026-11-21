/* x3_kc_adapter.c - runs the Keycloak client (src/kc/) on X3's event loop
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

/*
 * kc drives libcurl's multi interface and asks X3 for three things
 * (struct kc_event_ops): watch libcurl's sockets, run one timer at a time
 * with millisecond deadlines, and tell the time.
 *
 * Sockets.  libcurl owns its descriptors: it opens them, says which
 * direction it waits for (in, out or both), and before closing one it
 * says "remove" (kc_http.c: CURL_POLL_REMOVE -> socket_remove()).  Each
 * descriptor libcurl hands us gets its own io_fd, in state IO_CONNECTED,
 * found again by number through the list kc_socks (no limit on the
 * number or the count).  Interest maps onto the io_fd as
 *     in      read interest, writable_cb NULL
 *     out     no_reads set, writable_cb set
 *     in+out  read interest, writable_cb set
 * and a removal is ioset_close(io, 0): the registration goes away while
 * the number still names libcurl's socket, and libcurl closes it.
 *
 * Every one of these calls arrives from inside libcurl, often from inside
 * the readable_cb or writable_cb of some kc socket during an event pass:
 * a callback may change any socket's interest, remove any socket (its own
 * included), and add a socket under a number it just removed.  So:
 *   - a removal unlinks and frees the kc_sock at once and closes its
 *     io_fd; ioset keeps a closed io_fd allocated until the pass ends and
 *     delivers no more events to it, so the kc_sock pointer in its data
 *     is never read again;
 *   - nothing outside the list holds a kc_sock or an io_fd: an event
 *     callback copies what it needs into locals before calling into kc
 *     and touches neither afterwards;
 *   - a number added again gets a new kc_sock and a new io_fd, never the
 *     removed one, so a stale event cannot reach the new registration.
 *
 * Timers.  The adapter keeps its own list ordered by CLOCK_MONOTONIC
 * milliseconds and runs it from ioset's idle function, which also tells
 * ioset how long it may sleep.  timeq is not used: it counts whole
 * seconds, and kc's per-request limit is a number of milliseconds.
 *
 * Time.  kc_event_ops.now is X3's `now` (seconds), as kc expects.
 */

#include "common.h"
#include "ioset.h"
#include "log.h"
#include "x3_kc_adapter.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif

static struct log_type *KC_LOG;
static int adapter_ready;

/* ------------------------------------------------------------------ */
/* Sockets                                                            */
/* ------------------------------------------------------------------ */

struct kc_sock {
    int fd;
    int events;                 /* KC_EVENT_READ | KC_EVENT_WRITE */
    struct io_fd *io;           /* ours until socket_remove() */
    void (*callback)(int fd, int events, void *data);
    void *data;
    struct kc_sock *next;
};

/* Registrations libcurl has not removed.  A handful at a time (kc caps
 * libcurl at 64 connections), so a list searched by number is enough. */
static struct kc_sock *kc_socks;

static struct kc_sock *
kc_sock_find(int fd)
{
    struct kc_sock *sock;

    for (sock = kc_socks; sock; sock = sock->next)
        if (sock->fd == fd)
            return sock;
    return NULL;
}

static void
kc_sock_unlink(struct kc_sock *sock)
{
    struct kc_sock **pp;

    for (pp = &kc_socks; *pp; pp = &(*pp)->next) {
        if (*pp == sock) {
            *pp = sock->next;
            sock->next = NULL;
            return;
        }
    }
}

/* Hand one event to kc.  Nothing of sock is used after the call: kc may
 * remove this socket (freeing sock) or any other from inside it. */
static void
kc_sock_deliver(struct kc_sock *sock, int events)
{
    void (*callback)(int fd, int events, void *data) = sock->callback;
    void *data = sock->data;
    int fd = sock->fd;

    callback(fd, events, data);
}

static void
x3_kc_readable(struct io_fd *io)
{
    struct kc_sock *sock = io->data;

    if (!sock)
        return;
    if (sock->events & KC_EVENT_READ) {
        kc_sock_deliver(sock, KC_EVENT_READ);
    } else {
        /* Not waiting to read, so this is a hangup or an error.  kc has
         * no event for either: hand it both directions, so libcurl does
         * the I/O, sees the error and gives the socket up.  (The ircd's
         * adapter does the same.) */
        kc_sock_deliver(sock, KC_EVENT_READ | KC_EVENT_WRITE);
    }
}

static void
x3_kc_writable(struct io_fd *io)
{
    struct kc_sock *sock = io->data;

    if (!sock)
        return;
    kc_sock_deliver(sock, KC_EVENT_WRITE);
}

static void
kc_sock_set_interest(struct kc_sock *sock, int events)
{
    sock->events = events;
    sock->io->no_reads = !(events & KC_EVENT_READ);
    sock->io->writable_cb = (events & KC_EVENT_WRITE) ? x3_kc_writable : NULL;
    ioset_update(sock->io);
}

/* kc_event_ops.socket_add */
static int
x3_kc_socket_add(int fd, int events,
                 void (*callback)(int fd, int events, void *data), void *data)
{
    struct kc_sock *sock;
    struct io_fd *io;

    if (fd < 0 || !callback)
        return -1;

    if ((sock = kc_sock_find(fd)) != NULL) {
        /* Still registered: only the interest (and callback) change. */
        sock->callback = callback;
        sock->data = data;
        kc_sock_set_interest(sock, events);
        return 0;
    }

    sock = calloc(1, sizeof(*sock));
    if (!sock)
        return -1;
    io = ioset_add(fd);
    if (!io) {
        free(sock);
        return -1;
    }
    /* IO_CONNECTED at once: ioset ignores the events of an fd left in its
     * initial state, and epoll would report them again on every wait. */
    io->state = IO_CONNECTED;
    io->line_reads = 0;
    io->readable_cb = x3_kc_readable;
    io->data = sock;

    sock->fd = fd;
    sock->io = io;
    sock->callback = callback;
    sock->data = data;
    sock->next = kc_socks;
    kc_socks = sock;

    kc_sock_set_interest(sock, events);
    return 0;
}

/* kc_event_ops.socket_update */
static int
x3_kc_socket_update(int fd, int events)
{
    struct kc_sock *sock = kc_sock_find(fd);

    /* Never added, or removed already: the number may be someone else's. */
    if (!sock)
        return -1;
    kc_sock_set_interest(sock, events);
    return 0;
}

/* kc_event_ops.socket_remove */
static void
x3_kc_socket_remove(int fd)
{
    struct kc_sock *sock = kc_sock_find(fd);

    if (!sock)
        return;
    kc_sock_unlink(sock);
    /* Unregister now, while fd is still libcurl's socket; libcurl closes
     * it after we return (os_close 0).  If this io_fd's own event is
     * running, ioset frees it when the pass ends and sends it nothing
     * more, so its data pointer (sock, freed below) is not read again. */
    sock->io->data = NULL;
    ioset_close(sock->io, 0);
    free(sock);
}

/* ------------------------------------------------------------------ */
/* Timers                                                             */
/* ------------------------------------------------------------------ */

struct kc_timer {
    unsigned long long when;    /* monotonic milliseconds */
    unsigned long seq;          /* order of creation */
    void (*callback)(void *data);
    void *data;
    struct kc_timer *next;
};

/* Pending timers, earliest first (equal deadlines in creation order). */
static struct kc_timer *kc_timers;
static unsigned long kc_timer_seq;

static unsigned long long
kc_mono_ms(void)
{
#if defined(CLOCK_MONOTONIC)
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
        return (unsigned long long)ts.tv_sec * 1000ULL
            + (unsigned long long)(ts.tv_nsec / 1000000L);
#endif
    {
        struct timeval tv;

        gettimeofday(&tv, NULL);
        return (unsigned long long)tv.tv_sec * 1000ULL
            + (unsigned long long)(tv.tv_usec / 1000L);
    }
}

/* kc_event_ops.timer_add */
static void *
x3_kc_timer_add(unsigned long ms, void (*callback)(void *data), void *data)
{
    struct kc_timer *timer;
    struct kc_timer **pp;

    if (!callback)
        return NULL;
    timer = calloc(1, sizeof(*timer));
    if (!timer)
        return NULL;
    timer->when = kc_mono_ms() + ms;
    timer->seq = kc_timer_seq++;
    timer->callback = callback;
    timer->data = data;

    for (pp = &kc_timers; *pp && (*pp)->when <= timer->when; pp = &(*pp)->next)
        ;
    timer->next = *pp;
    *pp = timer;
    return timer;
}

/* Take timer out of the list.  Returns 0 if it is not there: only the
 * handle's address is compared, so a handle that already fired (and was
 * freed) is never dereferenced.  That is not ABA-safe: once a timer has
 * fired and been freed, a new timer may get the same address, and a late
 * cancel through the stale handle would remove the new one.  The callers
 * never cancel a spent handle -- kc drops its handle when a timer fires,
 * and the seam sets its own to NULL in the callback (rec_deadline(),
 * quiet_summary()) -- so this stays safe as long as they keep to that. */
static int
kc_timer_unlink(struct kc_timer *timer)
{
    struct kc_timer **pp;

    for (pp = &kc_timers; *pp; pp = &(*pp)->next) {
        if (*pp == timer) {
            *pp = timer->next;
            timer->next = NULL;
            return 1;
        }
    }
    return 0;
}

/* kc_event_ops.timer_cancel */
static void
x3_kc_timer_cancel(void *handle)
{
    struct kc_timer *timer = handle;

    if (timer && kc_timer_unlink(timer))
        free(timer);
}

/* ioset idle function: runs every timer that is due, then says how long
 * ioset may sleep (-1: no timer, 0: one is due now).  A timer added by a
 * callback of this run waits for the next run, even with 0 ms, so a
 * callback re-arming itself cannot keep this loop going. */
static long
x3_kc_idle(void)
{
    unsigned long long start = kc_mono_ms();
    unsigned long seq_limit = kc_timer_seq;
    unsigned long long cur;
    struct kc_timer *timer;
    void (*callback)(void *data);
    void *data;

    for (;;) {
        /* The first due timer that existed when this run began.  The list
         * may have changed under the previous callback: search afresh. */
        for (timer = kc_timers; timer && timer->when <= start; timer = timer->next)
            if (timer->seq < seq_limit)
                break;
        if (!timer || timer->when > start)
            break;
        kc_timer_unlink(timer);
        callback = timer->callback;
        data = timer->data;
        /* Freed before the call: the handle is spent once it fires (kc
         * forgets it first thing), and the callback may add a new one. */
        free(timer);
        callback(data);
    }

    if (!kc_timers)
        return -1;
    cur = kc_mono_ms();
    if (kc_timers->when <= cur)
        return 0;
    return (long)(kc_timers->when - cur);
}

/* ------------------------------------------------------------------ */
/* Time, poll hint, logging                                           */
/* ------------------------------------------------------------------ */

/* kc_event_ops.now: X3's clock, in seconds. */
static unsigned long
x3_kc_now(void)
{
    return (unsigned long)now;
}

/* kc_event_ops.poll_hint_ms: kc asks to be woken within a short time
 * because the timers it knew of counted whole seconds.  These timers
 * count milliseconds and set ioset's wait themselves: nothing to do. */
static void
x3_kc_poll_hint_ms(long timeout_ms)
{
    (void)timeout_ms;
}

/* kc_log_ops.log.  kc never puts the client secret in a message (it goes
 * only into request bodies), and neither does X3's own Keycloak code. */
static void
x3_kc_log(enum kc_log_level level, const char *fmt, ...)
{
    char buf[1024];
    enum log_severity sev;
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    switch (level) {
    case KC_LOG_DEBUG:   sev = LOG_DEBUG;   break;
    case KC_LOG_INFO:    sev = LOG_INFO;    break;
    case KC_LOG_WARNING: sev = LOG_WARNING; break;
    case KC_LOG_ERROR:   sev = LOG_ERROR;   break;
    default:             sev = LOG_INFO;    break;
    }
    if (KC_LOG)
        log_module(KC_LOG, sev, "%s", buf);
}

/* ------------------------------------------------------------------ */
/* Public                                                             */
/* ------------------------------------------------------------------ */

static const struct kc_event_ops x3_kc_event_ops = {
    .socket_add    = x3_kc_socket_add,
    .socket_update = x3_kc_socket_update,
    .socket_remove = x3_kc_socket_remove,
    .timer_add     = x3_kc_timer_add,
    .timer_cancel  = x3_kc_timer_cancel,
    .now           = x3_kc_now,
    .poll_hint_ms  = x3_kc_poll_hint_ms,
};

static const struct kc_log_ops x3_kc_log_ops = {
    .log = x3_kc_log,
};

void
x3_kc_adapter_init(void)
{
    if (adapter_ready)
        return;
    KC_LOG = log_register_type("keycloak", "file:keycloak.log");
    ioset_set_idle_func(x3_kc_idle);
    adapter_ready = 1;
}

const struct kc_event_ops *
x3_kc_get_event_ops(void)
{
    return &x3_kc_event_ops;
}

const struct kc_log_ops *
x3_kc_get_log_ops(void)
{
    return &x3_kc_log_ops;
}

void
x3_kc_adapter_cleanup(void)
{
    struct kc_sock *sock;
    struct kc_timer *timer;

    while ((sock = kc_socks) != NULL) {
        kc_socks = sock->next;
        sock->io->data = NULL;
        ioset_close(sock->io, 0);
        free(sock);
    }
    while ((timer = kc_timers) != NULL) {
        kc_timers = timer->next;
        free(timer);
    }
    if (adapter_ready)
        ioset_set_idle_func(NULL);
    adapter_ready = 0;
}
