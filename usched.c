/**
 * Copyright (c) 2012, PICHOT Fabien Paul Leonard <pichot.fabien@gmail.com>
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
**/

#include <errno.h>
#include <assert.h>
#include <event2/event.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "coro.h"
#include "usched.h"

struct rw_events
{
    struct event *r_event;
    struct event *w_event;
};

#define MAP_KEY_TYPE evutil_socket_t
#define MAP_VALUE_TYPE struct rw_events
#define MAP_PREFIX fd_ev
#include "map.h"

void sched_dispatch(evutil_socket_t fd, short event, void *ctx);

struct uthread_args
{
    struct uthread *fib;
    intptr_t userptr;
    int stopping;
};

struct rw_events *get_events(struct uthread_args *s, evutil_socket_t fd,
                             short event)
{
    struct rw_events *t;

    t = m_fd_ev_find(s->fib->map_fe, fd);
    if (t == NULL)
    {
        struct rw_events ev;

        ev.w_event = NULL;
        ev.r_event = NULL;
        if (event == EV_READ)
        {
            ev.r_event = event_new(s->fib->sched->evbase, fd, EV_READ,
                                   sched_dispatch, s->fib);
        }
        else if (event == EV_WRITE)
        {
            ev.w_event = event_new(s->fib->sched->evbase, fd, EV_WRITE,
                                   sched_dispatch, s->fib);
        }
        return m_fd_ev_insert(s->fib->map_fe, fd, ev);
    }
    else
    {
        if ((event == EV_READ && t->r_event != NULL) ||
            (event == EV_WRITE && t->w_event != NULL))
            return t;
        else
        {
            if (event == EV_READ)
            {
                t->r_event = event_new(s->fib->sched->evbase, fd,
                                       EV_READ, sched_dispatch, s->fib);
            }
            else if (event == EV_WRITE)
            {
                t->w_event = event_new(s->fib->sched->evbase, fd,
                                       EV_WRITE, sched_dispatch, s->fib);
            }
        }
        return t;
    }
    return NULL;
}

int async_event(struct uthread_args *s, evutil_socket_t fd, short flag,
                struct timeval *timeout)
{
    struct coro_context *origin = s->fib->sched->origin_ctx;
    struct rw_events *it;

    if (flag & EV_READ)
    {
        it = get_events(s, fd, EV_READ);
        if (it == NULL)
            return -1;
        event_add(it->r_event, timeout);
    }
    if (flag & EV_WRITE)
    {
        it = get_events(s, fd, EV_WRITE);
        if (it == NULL)
            return -1;
        event_add(it->w_event, timeout);
    }
    s->fib->fib_op.value = 0;
    coro_transfer(&s->fib->fib_ctx, origin);

    if (s->fib->fib_op.op_type == INTERUPTED)
    {
        errno = EINTR;
        return -1;
    }

    if (s->stopping == 1)
    {
        errno = EINTR;
        return -1;
    }

    return (int)s->fib->fib_op.value;
}

int async_multiple_event(struct uthread_args *s, evutil_socket_t *fd,
                         size_t fd_size, short flag, struct timeval *tv)
{
    struct coro_context *origin = s->fib->sched->origin_ctx;
    struct rw_events* events_array[fd_size];

    for (unsigned int i = 0; i < fd_size; ++i)
    {
        events_array[i] = get_events(s, fd[i], flag);
        if (flag & EV_READ)
            event_add(events_array[i]->r_event, tv);
        else if (flag & EV_WRITE)
            event_add(events_array[i]->w_event, tv);
    }

    s->fib->fib_op.value = 0;
    coro_transfer(&s->fib->fib_ctx, origin);

    for (unsigned int i = 0; i < fd_size; ++i)
    {
        if (flag & EV_READ)
            event_del(events_array[i]->r_event);
        else if (flag & EV_WRITE)
            event_del(events_array[i]->w_event);
    }

    return s->fib->fib_op.value;
}

ssize_t async_recvfrom(struct uthread_args *s, evutil_socket_t fd, char *buf,
                       int len, int flag, struct sockaddr *sock,
                       socklen_t *socklen)
{
    if (async_event(s, fd, EV_READ, NULL) == -1)
        return -1;
    return recvfrom(fd, buf, len, flag, sock, socklen);
}

evutil_socket_t async_accept(struct uthread_args *s, evutil_socket_t fd,
                             struct sockaddr *sock, socklen_t *socklen)
{
    if (async_event(s, fd, EV_READ, NULL) == -1)
        return -1;
    return accept4(fd, sock, socklen, SOCK_NONBLOCK | SOCK_CLOEXEC);
}

evutil_socket_t async_connect(struct uthread_args *s, evutil_socket_t fd,
                             struct sockaddr *sock, socklen_t socklen)
{
    int n = connect(fd, sock, socklen);
    if (n == -1 && errno != EINPROGRESS)
    {
        return -1;
    }
    if (errno == EINPROGRESS)
    {
        if (async_event(s, fd, EV_WRITE, NULL) == -1)
            return -1;

        int error = 0;
        socklen_t error_size = sizeof error;

        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &error_size) == -1)
            return -1;
        if (error == 0)
            return 0;
        else
        {
            errno = error;
            return -1;
        }
    }
    return 0;
}

void async_sleep(struct uthread_args *s, int time)
{
    struct timeval tv;
    struct coro_context *origin = s->fib->sched->origin_ctx;

    tv.tv_sec = time;
    tv.tv_usec = 0;
    event_add(s->fib->yield_event, &tv);
    coro_transfer(&s->fib->fib_ctx, origin);
}

ssize_t async_recv(struct uthread_args *s, evutil_socket_t fd, void *buf,
                   size_t len, int flags)
{
    if (async_event(s, fd, EV_READ, NULL) == -1)
        return -1;
    return recv(fd, buf, len, flags);
}

ssize_t async_send(struct uthread_args *s, evutil_socket_t fd, void const *buf,
                   size_t len, int flags)
{
    if (async_event(s, fd, EV_WRITE, NULL) == -1)
        return -1;
    return send(fd, buf, len, flags);
}

ssize_t async_read(struct uthread_args *s, evutil_socket_t fd, void *buf,
                   size_t len)
{
    if (async_event(s, fd, EV_READ, NULL) == -1)
        return -1;
    return read(fd, buf, len);
}

ssize_t async_write(struct uthread_args *s, evutil_socket_t fd, void const *buf,
                    size_t len)
{
    if (async_event(s, fd, EV_WRITE, NULL) == -1)
        return -1;
    return write(fd, buf, len);
}

ssize_t async_sendto(struct uthread_args *s, evutil_socket_t fd,
                     void const *buf, size_t len, int flags,
                     struct sockaddr const *dst, socklen_t socklen)
{
    if (async_event(s, fd, EV_WRITE, NULL) == -1)
        return -1;
    return sendto(fd, buf, len, flags, dst, socklen);
}

intptr_t async_yield(struct uthread_args *s, intptr_t yielded)
{
    struct coro_context *origin = s->fib->sched->origin_ctx;

    s->fib->fib_op.value = yielded;
    coro_transfer(&s->fib->fib_ctx, origin);

    if (s->stopping == 1)
    {
        errno = EINTR;
        return -1;
    }

    if (s->fib->fib_op.op_type == INTERUPTED)
    {
        errno = EINTR;
        return -1;
    }

    return s->fib->fib_op.value;
}

intptr_t async_continue(struct uthread_args *A, struct uthread *F,
                        intptr_t data)
{
    F->fib_op.value = data;
    event_active(F->yield_event, EV_TIMEOUT, /* unused */ 0);
    return async_yield(A, data);
}

void async_wake(struct uthread *F, intptr_t data)
{
    F->fib_op.value = data;
    event_active(F->yield_event, EV_TIMEOUT, /* Unused */ 0);
}

int async_signal(struct uthread_args* F, int signal)
{
    struct coro_context *origin = F->fib->sched->origin_ctx;
    struct event_base* base = F->fib->sched->evbase;

    struct event* event = evsignal_new(base, signal, sched_dispatch, F->fib);
    evsignal_add(event, NULL);

    F->fib->fib_op.value = 0;
    coro_transfer(&F->fib->fib_ctx, origin);
    if (F->fib->fib_op.op_type == INTERUPTED)
        return -1;
    return 0;
}

intptr_t sched_get_userptr(struct uthread_args *args) { return args->userptr; }

struct uthread *sched_get_uthread(struct uthread_args *args)
{
    return args->fib;
}

struct usched *sched_get_usched(struct uthread_args *args)
{
    return args->fib->sched;
}

struct event_base *sched_get_event_base(struct uthread_args *args)
{
    return args->fib->sched->evbase;
}

void sched_dispatch(evutil_socket_t fd, short event, void *ctx)
{
    struct uthread *fib = (struct uthread *)ctx;
    struct usched *S = fib->sched;
    struct coro_context cctx;

    coro_create(&cctx, NULL, NULL, NULL, 0);
    S->origin_ctx = &cctx;
    fib->fib_op.value = fd;
    coro_transfer(&cctx, &fib->fib_ctx);

    if (fib->fib_op.op_type == FREE)
    {
        struct uthread** ptr = v_uthread_find(&S->threads, fib);
        if (ptr != v_uthread_end(&S->threads))
            v_uthread_erase(&S->threads, ptr);

        coro_stack_free(&fib->fib_stack);
        free(fib);
    }
}

struct uthread *sched_new_uthread(struct usched *S, coro_func func,
                                  intptr_t userptr)
{
    struct uthread_args *args = calloc(sizeof(struct uthread_args), 1);
    struct uthread *new_uthread = calloc(sizeof(struct uthread), 1);

    if (new_uthread != NULL && args != NULL)
    {
        args->fib = new_uthread;
        args->userptr = userptr;
        args->fib->map_fe = m_fd_ev_new();

        coro_stack_alloc(&new_uthread->fib_stack, 1 << 17);
        new_uthread->fib_op.op_type = NONE;
        new_uthread->sched = S;
        new_uthread->dtor = NULL;
        new_uthread->dtor_ctx = 0;
        new_uthread->yield_event =
            event_new(S->evbase, -1, 0, sched_dispatch, new_uthread);
        event_add(new_uthread->yield_event, NULL);
        new_uthread->fib_args = args;

        coro_create(&new_uthread->fib_ctx, func, args,
                    new_uthread->fib_stack.sptr, new_uthread->fib_stack.ssze);

        return new_uthread;
    }

    free(new_uthread);
    free(args);
    return NULL;
}

void sched_uthread_launch(struct uthread *F)
{
    struct usched *S = F->sched;
    struct coro_context ctx;
    struct coro_context *save;

    save = S->origin_ctx;
    S->origin_ctx = &ctx;

    v_uthread_push(&S->threads, F);

    coro_create(&ctx, NULL, NULL, NULL, 0);
    coro_transfer(&ctx, &F->fib_ctx);

    S->origin_ctx = save;

    if (F->fib_op.op_type == FREE)
    {
        struct uthread** ptr = v_uthread_find(&S->threads, F);
        if (ptr != v_uthread_end(&S->threads))
            v_uthread_erase(&S->threads, ptr);

        coro_stack_free(&F->fib_stack);
        free(F);
    }
}

struct uthread *sched_uthread_start(struct usched *S, coro_func func, intptr_t userptr)
{
    struct uthread* t = sched_new_uthread(S, func, userptr);
    sched_uthread_launch(t);
    return t;
}

int sched_uthread_stopping(struct uthread_args* args)
{
    return args->stopping;
}

void sched_uthread_set_dtor(struct uthread *f,
                            void (*dtor)(struct uthread *, intptr_t),
                            intptr_t ctx)
{
    f->dtor = dtor;
    f->dtor_ctx = ctx;
}

void sched_uthread_exit(struct uthread_args *s, int val)
{
    coro_context *src;
    coro_context *dst;

    src = &s->fib->fib_ctx;
    dst = s->fib->sched->origin_ctx;

    struct uthread* F = s->fib;

    for (unsigned int i = 0; i < F->map_fe->vec->size; ++i)
    {
        struct map_pair_fd_ev * pair = &F->map_fe->vec->vec[i];

        struct event* w = pair->value.w_event;
        struct event* r = pair->value.r_event;

        if (w)
            event_free(w);

        if (r)
            event_free(r);
    }

    m_fd_ev_delete(F->map_fe);

    if (s->fib->yield_event != NULL)
        event_free(s->fib->yield_event);

    s->fib->fib_op.op_type = FREE;
    s->fib->fib_op.value = val;

    if (s->fib->dtor != NULL)
        s->fib->dtor(s->fib, s->fib->dtor_ctx);

    free(s);
    coro_transfer(src, dst);
}

void sched_uthread_delete(struct uthread *F)
{
    struct event_base* base = F->sched->evbase;

    F->fib_op.op_type = INTERUPTED;
    F->fib_op.value = 0;
    F->fib_args->stopping = 1;

    struct coro_context cctx;
    F->sched->origin_ctx = &cctx;
    coro_transfer(&cctx, &F->fib_ctx);

    coro_stack_free(&F->fib_stack);
    free(F);
}

struct usched *sched_new(struct event_base *evbase)
{
    struct usched *sched;

    sched = malloc(sizeof(*sched));
    memset(sched, 0, sizeof(*sched));
    sched->evbase = evbase;
    sched->origin_ctx = NULL;
    v_uthread_init(&sched->threads);
    return sched;
}

void sched_delete(struct usched *S)
{
    for (unsigned int i = 0; i < S->threads.size; ++i)
    {
        sched_uthread_delete(S->threads.vec[i]);
    }

    v_uthread_destroy(&S->threads);
    free(S);
}

