#pragma once

#include "misc.h"
#include "tag.h"
#include <stdbool.h>
#include <stddef.h>
#include <sys/socket.h>

#define CHINADNS_VERSION "2025.08.09-c"
#define CHINADNS_URL "https://github.com/zfl9/chinadns-ng"

struct strvec {
    char **items;
    size_t len;
    size_t cap;
};

void *xmalloc(size_t size);
void *xcalloc(size_t count, size_t size);
void *xrealloc(void *ptr, size_t size);
char *xstrdup(const char *str);
char *xstrndup(const char *str, size_t len);

void strvec_push(struct strvec *vec, const char *str);
void strvec_push_n(struct strvec *vec, const char *str, size_t len);

struct socket_addr {
    struct sockaddr_storage storage;
    socklen_t len;
};

bool socket_addr_parse(struct socket_addr *addr, const char *ip, u16 port);
int socket_addr_family(const struct socket_addr *addr);

int set_nonblocking(int fd);
int set_cloexec(int fd);
u64 now_msec(void);

struct message {
    u32 refs;
    u16 len;
    u16 cap;
    u8 data[];
};

struct message *message_new(size_t cap);
struct message *message_from(const void *data, size_t len);
struct message *message_ref(struct message *msg);
void message_unref(struct message *msg);

struct list_node {
    struct list_node *prev;
    struct list_node *next;
};

static inline void list_init(struct list_node *head) {
    head->prev = head;
    head->next = head;
}

static inline bool list_empty(const struct list_node *head) {
    return head->next == head;
}

static inline void list_insert_before(struct list_node *pos, struct list_node *node) {
    node->prev = pos->prev;
    node->next = pos;
    pos->prev->next = node;
    pos->prev = node;
}

static inline void list_insert_after(struct list_node *pos, struct list_node *node) {
    node->next = pos->next;
    node->prev = pos;
    pos->next->prev = node;
    pos->next = node;
}

static inline void list_remove(struct list_node *node) {
    node->prev->next = node->next;
    node->next->prev = node->prev;
    node->prev = node;
    node->next = node;
}

#define container_of(ptr, type, member) \
    ((type *)((char *)(ptr) - offsetof(type, member)))
