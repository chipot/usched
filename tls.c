#include <tls.h>
#include <event2/event.h>

#include "usched.h"

ssize_t async_tls_read(void* p, struct tls* ctx, int fd, void* buf, size_t buf_size)
{
    ssize_t ret;

again:
    ret = tls_read(ctx, buf, buf_size);
    
    if (ret == TLS_WANT_POLLIN)
    {
        if (async_event(p, fd, EV_READ, NULL) == -1)
            return -1;
        goto again;
    }

    if (ret == TLS_WANT_POLLOUT)
    {
        if (async_event(p, fd, EV_WRITE, NULL) == -1)
            return -1;
        goto again;
    }

    return ret;
}

ssize_t async_tls_write(void* p, struct tls* ctx, int fd, void* buf, size_t buf_size)
{
    ssize_t ret;

again:
    ret = tls_write(ctx, buf, buf_size);
    
    if (ret == TLS_WANT_POLLIN)
    {
        if (async_event(p, fd, EV_READ, NULL) == -1)
            return -1;
        goto again;
    }

    if (ret == TLS_WANT_POLLOUT)
    {
        if (async_event(p, fd, EV_WRITE, NULL) == -1)
            return -1;
        goto again;
    }

    return ret;
}

ssize_t async_tls_handshake(void* p, struct tls* ctx, int fd)
{
    ssize_t ret;
again:
    ret = tls_handshake(ctx);
    
    if (ret == TLS_WANT_POLLIN)
    {
        if (async_event(p, fd, EV_READ, NULL) == -1)
            return -1;
        goto again;
    }

    if (ret == TLS_WANT_POLLOUT)
    {
        if (async_event(p, fd, EV_WRITE, NULL) == -1)
            return -1;
        goto again;
    }

    return ret;
}

int async_tls_close(void* p, struct tls* ctx, int fd)
{
    ssize_t ret;
again:
    ret = tls_close(ctx);
    
    if (ret == TLS_WANT_POLLIN)
    {
        if (async_event(p, fd, EV_READ, NULL) == -1)
            return -1;
        goto again;
    }

    if (ret == TLS_WANT_POLLOUT)
    {
        if (async_event(p, fd, EV_WRITE, NULL) == -1)
            return -1;
        goto again;
    }

    return ret;
}

