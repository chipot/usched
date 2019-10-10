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

#ifndef SCHED_O6L1KITS
#define SCHED_O6L1KITS

#include "coro.h"
#include <event2/util.h>

struct uthread_args;
struct map_fd_evl;

enum sched_operation
{
    NONE = 0,
    FREE,
    INTERUPTED,
};

struct operation
{
    enum sched_operation op_type;
    intptr_t value;
};

struct uthread
{
    struct coro_context fib_ctx;
    struct coro_stack fib_stack;

    struct operation fib_op;

    struct usched *sched;

    struct event *yield_event;

    struct map_fd_ev *map_fe;
    void (*dtor)(struct uthread *, intptr_t);
    intptr_t dtor_ctx;

    struct uthread_args* fib_args;
};

#define VECTOR_TYPE struct uthread *
#define VECTOR_PREFIX uthread
#define VECTOR_TYPE_SCALAR
#define DEFAULT_ALLOC_SIZE 4
#include "vector.h"

struct usched
{
    struct event_base *evbase;
    struct coro_context *origin_ctx;
    struct vector_uthread threads;
};

struct usched *sched_new(struct event_base *);

void sched_delete(struct usched *);

struct uthread *sched_new_uthread(struct usched *S, coro_func func, intptr_t userptr);
void sched_uthread_launch(struct uthread *F);

struct uthread *sched_uthread_start(struct usched *, coro_func func, intptr_t userptr);

void sched_uthread_delete(struct uthread *);

void sched_uthread_set_dtor(struct uthread *,
                            void (*dtor)(struct uthread *, intptr_t),
                            intptr_t ctx);

void sched_uthread_exit(struct uthread_args *, int val);


intptr_t sched_get_userptr(struct uthread_args *args);
struct uthread *sched_get_uthread(struct uthread_args *args);
struct usched *sched_get_usched(struct uthread_args *args);
struct event_base* sched_get_event_base(struct uthread_args* args);

int sched_uthread_stopping(struct uthread_args*);

// syscalls

void async_sleep(struct uthread_args *args, int sec);

int async_event(struct uthread_args *s, evutil_socket_t fd, short flag, struct timeval*);

intptr_t async_yield(struct uthread_args *S, intptr_t yielded);

intptr_t async_continue(struct uthread_args *A, struct uthread *F,
                        intptr_t data);

void async_wake(struct uthread *F, intptr_t data);

ssize_t async_sendto(struct uthread_args *s, evutil_socket_t fd,
                     void const *buf, size_t len, int flag,
                     struct sockaddr const *sock, socklen_t socklen);

ssize_t async_send(struct uthread_args *s, evutil_socket_t fd, void const *buf,
                   size_t len, int flag);

ssize_t async_read(struct uthread_args *s, evutil_socket_t fd, void *buf,
                   size_t len);

ssize_t async_recv(struct uthread_args *s, evutil_socket_t fd, void *buf,
                   size_t len, int flag);

ssize_t async_write(struct uthread_args *s, evutil_socket_t fd, void const *buf,
                    size_t len);

ssize_t async_recvfrom(struct uthread_args *s, evutil_socket_t fd, char *buf,
                       int len, int flag, struct sockaddr *sock,
                       socklen_t *socklen);

evutil_socket_t async_accept(struct uthread_args *s, evutil_socket_t fd,
                             struct sockaddr *sock, socklen_t *socklen);

int async_connect(struct uthread_args *s, evutil_socket_t fd,
                  struct sockaddr *sock, socklen_t socklen);

// signals

int async_signal(struct uthread_args*, int signal);

// tls

struct tls;

ssize_t async_tls_read(void* p, struct tls* ctx, int fd, void* buf, size_t buf_size);
ssize_t async_tls_write(void* p, struct tls* ctx, int fd, void* buf, size_t buf_size);
ssize_t async_tls_handshake(void* p, struct tls* ctx, int fd);
int async_tls_close(void* p, struct tls* ctx, int fd);

// imsgs

struct imsgbuf;
struct imsg;
struct msgbuf;

struct uimsg_sender;

ssize_t async_imsg_get(void*, struct imsgbuf*, struct imsg*);
ssize_t async_msgbuf_write(void*, struct msgbuf*);
struct uimsg_sender *sched_uthread_imsg_sender(struct usched *, struct imsgbuf*, char const*);
int async_imsg_compose(struct uthread_args*, struct uimsg_sender *, u_int32_t, u_int32_t, pid_t, int,
                       const void *, u_int16_t);

#endif /* end of include guard: SCHED_O6L1KITS */
