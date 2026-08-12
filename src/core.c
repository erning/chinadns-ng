#define _GNU_SOURCE
#include "core.h"
#include "log.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

bool log_verbose_enabled = false;

static void oom(void) {
    fputs("chinadns-ng: out of memory\n", stderr);
    abort();
}

void *xmalloc(size_t size) {
    void *ptr = malloc(size ? size : 1);
    if (!ptr) oom();
    return ptr;
}

void *xcalloc(size_t count, size_t size) {
    void *ptr = calloc(count ? count : 1, size ? size : 1);
    if (!ptr) oom();
    return ptr;
}

void *xrealloc(void *ptr, size_t size) {
    ptr = realloc(ptr, size ? size : 1);
    if (!ptr) oom();
    return ptr;
}

char *xstrdup(const char *str) {
    char *copy = strdup(str);
    if (!copy) oom();
    return copy;
}

char *xstrndup(const char *str, size_t len) {
    char *copy = xmalloc(len + 1);
    memcpy(copy, str, len);
    copy[len] = '\0';
    return copy;
}

void strvec_push_n(struct strvec *vec, const char *str, size_t len) {
    if (vec->len == vec->cap) {
        vec->cap = vec->cap ? vec->cap * 2 : 4;
        vec->items = xrealloc(vec->items, vec->cap * sizeof(*vec->items));
    }
    vec->items[vec->len++] = xstrndup(str, len);
}

void strvec_push(struct strvec *vec, const char *str) {
    strvec_push_n(vec, str, strlen(str));
}

bool socket_addr_parse(struct socket_addr *addr, const char *ip, u16 port) {
    memset(addr, 0, sizeof(*addr));

    struct sockaddr_in *v4 = (struct sockaddr_in *)&addr->storage;
    if (inet_pton(AF_INET, ip, &v4->sin_addr) == 1) {
        v4->sin_family = AF_INET;
        v4->sin_port = htons(port);
        addr->len = sizeof(*v4);
        return true;
    }

    struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&addr->storage;
    if (inet_pton(AF_INET6, ip, &v6->sin6_addr) == 1) {
        v6->sin6_family = AF_INET6;
        v6->sin6_port = htons(port);
        addr->len = sizeof(*v6);
        return true;
    }

    return false;
}

int socket_addr_family(const struct socket_addr *addr) {
    return addr->storage.ss_family;
}

int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
        return -1;
    return 0;
}

int set_cloexec(int fd) {
    int flags = fcntl(fd, F_GETFD, 0);
    if (flags < 0 || fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0)
        return -1;
    return 0;
}

u64 now_msec(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return (u64)ts.tv_sec * 1000 + (u64)ts.tv_nsec / 1000000;
}

struct message *message_new(size_t cap) {
    if (cap > UINT16_MAX) {
        errno = EOVERFLOW;
        return NULL;
    }
    struct message *msg = xmalloc(sizeof(*msg) + cap);
    msg->refs = 1;
    msg->len = 0;
    msg->cap = (u16)cap;
    return msg;
}

struct message *message_from(const void *data, size_t len) {
    struct message *msg = message_new(len);
    if (!msg) return NULL;
    memcpy(msg->data, data, len);
    msg->len = (u16)len;
    return msg;
}

struct message *message_ref(struct message *msg) {
    if (msg) {
        if (msg->refs == UINT32_MAX) abort();
        ++msg->refs;
    }
    return msg;
}

void message_unref(struct message *msg) {
    if (msg && --msg->refs == 0)
        free(msg);
}
