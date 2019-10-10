#include <stdlib.h>
#include <stdint.h>

#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <event2/event.h>

#include "log.h"
#include "imsg.h"
#include "usched.h"

LOG_DOMAIN(imsg, unpriv)

ssize_t async_imsg_get(void* uctx, struct imsgbuf* ibuf, struct imsg* imsg)
{
    ssize_t n = 0;
    errno = 0;
get_again:
    n = imsg_get(ibuf, imsg);
    if (n == -1)
        return -1;

    if (n == 0)
    {
read_again:
        if (async_event(uctx, ibuf->fd, EV_READ, NULL) == -1)
            return -1;
        n = imsg_read(ibuf);
        if (errno == EAGAIN)
            goto read_again;
        if (n == -1)
            return -1;
        goto get_again;
    }
    return n;
}


ssize_t
async_msgbuf_write(void* uctx, struct msgbuf *msgbuf)
{
    ssize_t n = 0;
again:
    if (async_event(uctx, msgbuf->fd, EV_WRITE, NULL) == -1)
        return -1;

    n = msgbuf_write(msgbuf);
    if (errno == EAGAIN)
        goto again;

    if (n < 0 && errno != EAGAIN)
    {
        return -1;
    }

    return n;
}

struct usched_imsg_sender_ctx {
    struct imsgbuf* ibuf;
    char const* name;
};

static void usched_imsg_sender(void* uctx)
{
    struct usched_imsg_sender_ctx* ctx = (struct usched_imsg_sender_ctx*)sched_get_userptr(uctx);
    struct imsgbuf* ibuf = ctx->ibuf;

    int stop = 0;
    while (sched_uthread_stopping(uctx) == 0 && stop == 0)
    {
        if (ibuf->w.queued == 0)
        {
            async_yield(uctx, 0);
            continue;
        }

        async_event(uctx, ibuf->fd, EV_WRITE, NULL);
        unsigned int cnt = 0;
        while (ibuf->w.queued)
        {
            if (msgbuf_write(&ibuf->w) <= 0)
                log_errno(&imsg_dom, "[%s]: msgbuf_write", ctx->name);
            else
                cnt++;
        }
    }

    free(ctx);
    sched_uthread_exit(uctx, 0);
}

struct uimsg_sender
{
    struct uthread* thr;
    struct imsgbuf* imsg;
    char const* name;
};

struct uimsg_sender* sched_uthread_imsg_sender(struct usched* sched, struct imsgbuf* buf, char const* name)
{
    struct uimsg_sender* ctx = (struct uimsg_sender*)calloc(sizeof(*ctx), 1);

    struct usched_imsg_sender_ctx* ctx2 = calloc(sizeof(*ctx2), 1);
    ctx2->ibuf = buf;
    ctx2->name = name;

    ctx->thr = sched_uthread_start(sched, usched_imsg_sender, (uintptr_t)ctx2);
    ctx->imsg = buf;

    return ctx;
}

int async_imsg_compose(struct uthread_args* uctx, struct uimsg_sender* ctx, u_int32_t type,
                       u_int32_t peerid, pid_t pid, int fd, const void* data,
                       u_int16_t datalen)
{
    int n = imsg_compose(ctx->imsg, type, peerid, pid, fd, data, datalen);
    async_wake(ctx->thr, 0);
    return n;
}
