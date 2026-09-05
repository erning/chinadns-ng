#define _GNU_SOURCE
#include "server.h"
#include "cache.h"
#include "config.h"
#include "core.h"
#include "dnl.h"
#include "dns.h"
#include "ipset.h"
#include "local_rr.h"
#include "log.h"
#include "net.h"
#include "wolfssl.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#ifndef SO_REUSEPORT
#define SO_REUSEPORT 15
#endif

#define MAX_EVENTS 64
#define QUERY_INITIAL_BUCKETS 1024
#define MAX_CLIENT_OUTPUT (1024U * 1024U)

enum source_kind {
    SOURCE_UDP_LISTENER,
    SOURCE_TCP_LISTENER,
    SOURCE_TCP_CLIENT,
    SOURCE_UPSTREAM_UDP,
    SOURCE_UPSTREAM_TCP,
    SOURCE_SIGNAL,
};

struct event_source {
    int fd;
    u32 events;
    enum source_kind kind;
    bool closed;
};

struct listener {
    struct event_source source;
    struct listener *next;
    struct socket_addr addr;
    char ip[INET6_ADDRSTRLEN];
    u16 port;
};

struct out_chunk {
    struct out_chunk *next;
    size_t len;
    size_t off;
    u8 data[];
};

struct tcp_client {
    struct event_source source;
    struct tcp_client *next;
    struct socket_addr peer;
    unsigned refs;
    bool read_closed;
    size_t input_len;
    size_t out_bytes;
    struct out_chunk *out_head;
    struct out_chunk *out_tail;
    u8 input[2 + DNS_QMSG_MAXSIZE];
};

enum query_from { QUERY_UDP, QUERY_TCP, QUERY_LOCAL };
enum query_verdict { VERDICT_UNKNOWN, VERDICT_CHINA, VERDICT_NON_CHINA };

/* embedded in every session entry (udp pending id / tcp request): links the
 * entry back to the query it was sent for, so query_delete can release its
 * entries directly instead of cleanup_pending scanning for orphans. `query`
 * is NULL once the query is gone (the entry is then an orphan, kept only on
 * linger sessions until expire_at). */
struct query_ref {
    struct query_ref *q_next; /* next entry of the same query */
    struct query *query;
    struct upstream_session *session;
    const u8 *question;
    u8 qnamelen;
};

struct query {
    struct query *hash_next;
    struct list_node deadline;
    struct query_ref *refs; /* session entries still holding this query */
    u64 request_time;
    u16 qid;
    u16 original_id;
    u16 bufsz;
    u16 qtype;
    u8 tag;
    u8 qnamelen;
    bool cacheable;
    enum query_from from;
    enum query_verdict verdict;
    struct listener *udp_listener;
    struct socket_addr peer;
    struct tcp_client *tcp_client;
    struct message *trust_reply;
};

/* session entries are kept in send order, so `expire_at` grows along the list
 * and the entries to purge are always a prefix (see cleanup_pending) */
struct pending_id {
    struct pending_id *next;
    struct pending_id *prev;
    struct query_ref ref;
    u16 qid;
    u64 expire_at; /* monotime(ms) after which a lingering entry is purged */
    u8 question[];
};

struct tcp_request {
    struct tcp_request *next;
    struct tcp_request *prev;
    struct query_ref ref;
    size_t offset;
    size_t frame_len;
    u16 qid;
    u64 expire_at; /* monotime(ms) after which a lingering entry is purged */
    bool sent;
    bool write_started; /* TLS may buffer bytes even when offset is still zero */
    u8 frame[];
};

enum tcp_state { TCP_DOWN, TCP_CONNECTING, TCP_TLS_HANDSHAKE, TCP_READY };

struct upstream_session {
    struct event_source source;
    struct upstream_session *next;
    struct upstream_config *config;
    u64 create_time;
    u64 retry_at;
    u64 oldest_linger_at; /* earliest expire_at among lingering entries; 0 = none */
    u16 query_count;
    u32 pending_count;
    bool retired;
    bool tcp;
    union {
        struct {
            struct pending_id *head;
            struct pending_id *tail;
        } udp;
        struct {
            enum tcp_state state;
            struct tcp_request *head;
            struct tcp_request *tail;
            u8 len_buf[2];
            size_t len_have;
            struct message *input;
            size_t input_have;
#ifdef ENABLE_WOLFSSL
            WOLFSSL *ssl;
            u32 tls_want;
            u32 tls_read_want;
            u32 tls_write_want;
#endif
        } tcp;
    } u;
};

static int epoll_fd = -1;
static struct listener *listeners;
static struct tcp_client *clients;
static struct upstream_session *sessions;
static struct event_source signal_source = { .fd = -1, .closed = true };
static struct query **query_buckets;
static size_t query_bucket_count;
static struct list_node query_deadlines;
static size_t query_count;
static u16 last_qid;
static bool running = true;
static const struct ipset_testctx *ip_testctx;
static struct ipset_addctx *ip_addctx[TAG_NONE + 1];
#ifdef ENABLE_WOLFSSL
static WOLFSSL_CTX *tls_ctx;
#endif

static bool source_add(struct event_source *source, int fd, enum source_kind kind, u32 events) {
    source->fd = fd;
    source->kind = kind;
    source->events = events;
    source->closed = false;
    struct epoll_event ev = { .events = events, .data.ptr = source };
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0) {
        log_warning("epoll add fd:%d failed: (%d) %s", fd, errno, strerror(errno));
        close(fd);
        source->fd = -1;
        source->closed = true;
        return false;
    }
    return true;
}

static void source_mod(struct event_source *source, u32 events) {
    if (source->closed || source->events == events) return;
    source->events = events;
    struct epoll_event ev = { .events = events, .data.ptr = source };
    if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, source->fd, &ev) < 0 && errno != ENOENT)
        log_warning("epoll mod fd:%d failed: (%d) %s", source->fd, errno, strerror(errno));
}

static void source_detach(struct event_source *source) {
    if (source->closed) return;
    source->closed = true;
    if (source->fd >= 0) {
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, source->fd, NULL);
        close(source->fd);
        source->fd = -1;
    }
}

static int new_socket(int family, int type) {
    int fd = socket(family, type | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0 && (errno == EINVAL || errno == EPROTONOSUPPORT)) {
        fd = socket(family, type, 0);
        if (fd >= 0 && (set_nonblocking(fd) < 0 || set_cloexec(fd) < 0)) {
            close(fd);
            fd = -1;
        }
    }
    return fd;
}

static void client_close(struct tcp_client *client) {
    if (client->source.closed) return;
    source_detach(&client->source);
    while (client->out_head) {
        struct out_chunk *next = client->out_head->next;
        free(client->out_head);
        client->out_head = next;
    }
    client->out_tail = NULL;
    client->out_bytes = 0;
}

static void client_update_events(struct tcp_client *client) {
    if (client->source.closed) return;
    u32 events = 0;
    if (!client->read_closed) events |= EPOLLIN | EPOLLRDHUP;
    if (client->out_head) events |= EPOLLOUT;
    source_mod(&client->source, events);
}

static void client_read_eof(struct tcp_client *client) {
    client->read_closed = true;
    if (!client->refs && !client->out_head)
        client_close(client);
    else
        client_update_events(client);
}

static void clients_sweep(void) {
    struct tcp_client **p = &clients;
    while (*p) {
        struct tcp_client *client = *p;
        if (client->source.closed && client->refs == 0) {
            *p = client->next;
            free(client);
        } else {
            p = &client->next;
        }
    }
}

static void client_queue_reply(struct tcp_client *client, const void *data, size_t len) {
    if (client->source.closed || len > UINT16_MAX) return;
    if (2 + len > MAX_CLIENT_OUTPUT - client->out_bytes) {
        log_warning("close slow TCP client fd:%d: output queue exceeds %u bytes",
            client->source.fd, MAX_CLIENT_OUTPUT);
        client_close(client);
        return;
    }
    struct out_chunk *chunk = xmalloc(sizeof(*chunk) + 2 + len);
    chunk->next = NULL;
    chunk->len = 2 + len;
    chunk->off = 0;
    chunk->data[0] = (u8)(len >> 8);
    chunk->data[1] = (u8)len;
    memcpy(chunk->data + 2, data, len);
    if (client->out_tail) client->out_tail->next = chunk;
    else client->out_head = chunk;
    client->out_tail = chunk;
    client->out_bytes += chunk->len;
    client_update_events(client);
}

static void client_write(struct tcp_client *client) {
    while (client->out_head) {
        struct out_chunk *chunk = client->out_head;
        ssize_t n = send(client->source.fd, chunk->data + chunk->off, chunk->len - chunk->off, MSG_NOSIGNAL);
        if (n > 0) {
            chunk->off += (size_t)n;
            client->out_bytes -= (size_t)n;
            if (chunk->off < chunk->len) continue;
            client->out_head = chunk->next;
            if (!client->out_head) client->out_tail = NULL;
            free(chunk);
        } else if (n < 0 && errno == EINTR) {
            continue;
        } else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return;
        } else {
            client_close(client);
            return;
        }
    }
    if (client->read_closed && !client->refs)
        client_close(client);
    else
        client_update_events(client);
}

static size_t query_bucket(u16 qid) {
    return qid & (query_bucket_count - 1);
}

static void query_grow(void) {
    if (query_count < query_bucket_count * 2 || query_bucket_count >= 32768) return;
    size_t new_count = query_bucket_count * 2;
    struct query **new_buckets = xcalloc(new_count, sizeof(*new_buckets));
    for (size_t i = 0; i < query_bucket_count; ++i) {
        struct query *q = query_buckets[i];
        while (q) {
            struct query *next = q->hash_next;
            size_t idx = q->qid & (new_count - 1);
            q->hash_next = new_buckets[idx];
            new_buckets[idx] = q;
            q = next;
        }
    }
    free(query_buckets);
    query_buckets = new_buckets;
    query_bucket_count = new_count;
}

static struct query *query_find(u16 qid) {
    for (struct query *q = query_buckets[query_bucket(qid)]; q; q = q->hash_next)
        if (q->qid == qid) return q;
    return NULL;
}

/* lingering session entries (and their tcp resend) only serve the passive
 * health-check: only a primary (non-fallback) upstream of a group that has
 * ?fallback upstream(s) needs late replies to still match, as recovery
 * signals. every other session releases its entries as soon as the query is
 * done, exactly like before this feature. */
static bool session_needs_linger(const struct upstream_session *s) {
    return g_config.groups[s->config->tag].fallback_enabled && !s->config->fallback;
}

/* detach the entry from the query that owns it; the entry itself survives as
 * an orphan (only linger sessions keep those, until expire_at) */
static void query_ref_release(struct query_ref *ref) {
    if (!ref->query) return;
    struct query_ref **p = &ref->query->refs;
    while (*p && *p != ref) p = &(*p)->q_next;
    if (*p) *p = ref->q_next;
    ref->query = NULL;
    ref->q_next = NULL;
}

/* unlink from the session and free; the caller has released the query ref */
static void udp_pending_free(struct upstream_session *s, struct pending_id *id) {
    if (id->prev) id->prev->next = id->next;
    else s->u.udp.head = id->next;
    if (id->next) id->next->prev = id->prev;
    else s->u.udp.tail = id->prev;
    free(id);
    --s->pending_count;
}

static void tcp_request_free(struct upstream_session *s, struct tcp_request *req) {
    if (req->prev) req->prev->next = req->next;
    else s->u.tcp.head = req->next;
    if (req->next) req->next->prev = req->prev;
    else s->u.tcp.tail = req->prev;
    free(req);
    --s->pending_count;
}

static void tcp_disconnect(struct upstream_session *s, bool retry);
static void tcp_update_events(struct upstream_session *s);

/* Only fully sent requests can linger for a late health-check reply. Never
 * discard a partial frame while keeping its byte stream open. */
static void query_release_refs(struct query *q) {
    while (q->refs) {
        struct query_ref *ref = q->refs;
        struct upstream_session *s = ref->session;
        query_ref_release(ref);
        if (s->tcp) {
            struct tcp_request *req = container_of(ref, struct tcp_request, ref);
            if (!req->sent && req->write_started) {
                /* Drops this orphan and resets live requests for reconnect. */
                tcp_disconnect(s, true);
            } else if (!req->sent || !session_needs_linger(s)) {
                tcp_request_free(s, req);
                tcp_update_events(s);
            }
        } else if (!session_needs_linger(s)) {
            udp_pending_free(s, container_of(ref, struct pending_id, ref));
        }
        if (s->retired && !s->pending_count) source_detach(&s->source);
    }
}

static void query_delete(struct query *q) {
    struct query **p = &query_buckets[query_bucket(q->qid)];
    while (*p && *p != q) p = &(*p)->hash_next;
    if (*p) *p = q->hash_next;
    list_remove(&q->deadline);
    query_release_refs(q);
    message_unref(q->trust_reply);
    if (q->tcp_client) {
        if (!q->tcp_client->refs) abort();
        --q->tcp_client->refs;
        if (q->tcp_client->read_closed && !q->tcp_client->refs && !q->tcp_client->out_head)
            client_close(q->tcp_client);
    }
    free(q);
    --query_count;
}

static struct query *query_new(struct message *msg, int qnamelen, u16 qtype,
    u8 tag, u16 bufsz, enum query_from from, struct listener *udp_listener,
    const struct socket_addr *peer, struct tcp_client *tcp_client) {
    if (query_count >= 65536) {
        log_warning("too many pending queries");
        return NULL;
    }
    u16 qid = 0;
    bool found = false;
    for (unsigned i = 0; i < 65536; ++i) {
        qid = ++last_qid;
        if (!query_find(qid)) { found = true; break; }
    }
    if (!found) return NULL;
    query_grow();
    struct query *q = xcalloc(1, sizeof(*q));
    q->request_time = now_msec();
    q->qid = qid;
    q->original_id = dns_get_id(msg->data);
    q->bufsz = bufsz;
    q->qtype = qtype;
    q->tag = tag;
    q->qnamelen = (u8)qnamelen;
    q->from = from;
    q->udp_listener = udp_listener;
    if (peer) q->peer = *peer;
    q->tcp_client = tcp_client;
    if (tcp_client) ++tcp_client->refs;
    dns_set_id(msg->data, qid);
    size_t idx = query_bucket(qid);
    q->hash_next = query_buckets[idx];
    query_buckets[idx] = q;
    list_insert_before(&query_deadlines, &q->deadline);
    ++query_count;
    return q;
}

static void send_reply_to_query(struct query *q, struct message *msg) {
    if (q->from == QUERY_LOCAL) return;
    dns_set_id(msg->data, q->original_id);
    const void *data = msg->data;
    size_t len = msg->len;
    u8 truncated[DNS_QMSG_MAXSIZE];
    if (q->from == QUERY_UDP && len > q->bufsz) {
        len = dns_truncate(data, (ssize_t)len, truncated);
        data = truncated;
    }
    if (q->from == QUERY_UDP) {
        ssize_t n = sendto(q->udp_listener->source.fd, data, len, 0,
            (const struct sockaddr *)&q->peer.storage, q->peer.len);
        if (n < 0) log_warning("send UDP reply failed: (%d) %s", errno, strerror(errno));
    } else {
        client_queue_reply(q->tcp_client, data, len);
    }
}

static void send_immediate(struct message *msg, int qnamelen, u16 original_id,
    u16 bufsz, enum query_from from, struct listener *udp_listener,
    const struct socket_addr *peer, struct tcp_client *tcp_client) {
    struct query temp = {
        .original_id = original_id, .bufsz = bufsz, .from = from,
        .udp_listener = udp_listener, .tcp_client = tcp_client,
    };
    if (peer) temp.peer = *peer;
    send_reply_to_query(&temp, msg);
    (void)qnamelen;
}

static void send_bad_query_reply(struct message *msg, enum query_from from,
    struct listener *udp_listener, const struct socket_addr *peer,
    struct tcp_client *tcp_client) {
    if (msg->len >= dns_header_len())
        msg->len = dns_empty_reply(msg->data, 0);
    if (from == QUERY_UDP) {
        sendto(udp_listener->source.fd, msg->data, msg->len, 0,
            (const struct sockaddr *)&peer->storage, peer->len);
    } else if (from == QUERY_TCP) {
        client_queue_reply(tcp_client, msg->data, msg->len);
    }
}

static bool session_should_retire(struct upstream_session *s) {
    return (s->config->count && s->query_count >= s->config->count) ||
        (s->config->life && now_msec() >= s->create_time + (u64)s->config->life * 1000);
}

static void session_mark_retired(struct upstream_session *s) {
    s->retired = true;
    if (s->config->runtime == s) s->config->runtime = NULL;
    if (!s->pending_count) source_detach(&s->source);
}

static void udp_pending_add(struct upstream_session *s, struct query *q, struct message *msg) {
    size_t question_len = dns_question_len(q->qnamelen);
    struct pending_id *id = xcalloc(1, sizeof(*id) + question_len);
    id->qid = q->qid;
    id->expire_at = now_msec() + (u64)g_config.upstream_timeout * 1000;
    id->ref.session = s;
    id->ref.query = q;
    id->ref.qnamelen = q->qnamelen;
    id->ref.question = id->question;
    memcpy(id->question, msg->data + dns_header_len(), question_len);
    id->ref.q_next = q->refs;
    q->refs = &id->ref;
    /* appended, so the list stays ordered by expire_at */
    id->prev = s->u.udp.tail;
    if (s->u.udp.tail) s->u.udp.tail->next = id;
    else s->u.udp.head = id;
    s->u.udp.tail = id;
    ++s->pending_count;
}

static bool query_ref_matches(const struct query_ref *ref, const void *reply, int qnamelen) {
    return ref->qnamelen == qnamelen && dns_question_equal(ref->question,
        (const u8 *)reply + dns_header_len(), qnamelen);
}

static bool udp_pending_remove(struct upstream_session *s, u16 qid,
    const void *reply, int qnamelen, struct query **query) {
    /* Prefer the newest entry with an equivalent question after ID reuse. */
    struct pending_id *id = s->u.udp.tail;
    while (id && (id->qid != qid || !query_ref_matches(&id->ref, reply, qnamelen))) id = id->prev;
    if (!id) return false;
    *query = id->ref.query;
    query_ref_release(&id->ref);
    udp_pending_free(s, id);
    if (s->retired && !s->pending_count) source_detach(&s->source);
    return true;
}

static void upstream_on_reply(struct upstream_session *session, struct message *reply);

static void udp_session_read(struct upstream_session *s) {
    for (;;) {
        struct message *msg = message_new(DNS_EDNS_MAXSIZE);
        struct socket_addr peer = { .len = sizeof(peer.storage) };
        ssize_t n = recvfrom(s->source.fd, msg->data, msg->cap, 0,
            (struct sockaddr *)&peer.storage, &peer.len);
        if (n > 0) {
            /* the socket only ever queries config->addr: a reply from any other
             * source is unsolicited (spoofed) and must be dropped */
            if (peer.len != s->config->addr.len ||
                memcmp(&peer.storage, &s->config->addr.storage, peer.len) != 0) {
                log_verbose("ignore reply from unexpected peer of %s", s->config->url);
            } else {
                msg->len = (u16)n;
                upstream_on_reply(s, msg);
            }
            message_unref(msg);
            /* on_reply may have detached the source (last pending entry of a
             * retired session): stop before touching the dead fd */
            if (s->source.closed) return;
        } else {
            message_unref(msg);
            if (n < 0 && errno == EINTR) continue;
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
            if (n < 0) log_warning("recv(%s) failed: (%d) %s", s->config->url, errno, strerror(errno));
            return;
        }
    }
}

/* remove the request of qmsg; returns whether the reply matched one of this
 * session's outstanding queries (gates the passive health-check recovery) */
static bool tcp_request_remove(struct upstream_session *s, u16 qid,
    const void *reply, int qnamelen, struct query **query) {
    /* newest first, see udp_pending_remove */
    struct tcp_request *req = s->u.tcp.tail;
    while (req && (req->qid != qid || !req->sent ||
        !query_ref_matches(&req->ref, reply, qnamelen))) req = req->prev;
    if (!req) return false;
    *query = req->ref.query;
    query_ref_release(&req->ref);
    tcp_request_free(s, req);
    return true;
}

/* remove the pending entry of qid; returns whether the reply matched one of
 * this session's outstanding queries. called from upstream_on_reply only
 * after the reply passed validation, so a malformed reply does not consume
 * the entry (and thus cannot silence a later real reply).
 * Return the entry's owning query, which is NULL for lingering orphans;
 * never associate an orphan's reply with a new query that reused its ID. */
static bool session_pending_remove(struct upstream_session *s, u16 qid,
    const void *reply, int qnamelen, struct query **query) {
    return s->tcp ? tcp_request_remove(s, qid, reply, qnamelen, query) :
        udp_pending_remove(s, qid, reply, qnamelen, query);
}

static void tcp_reset_input(struct upstream_session *s) {
    message_unref(s->u.tcp.input);
    s->u.tcp.input = NULL;
    s->u.tcp.input_have = 0;
    s->u.tcp.len_have = 0;
}

#ifdef ENABLE_WOLFSSL
static bool session_is_tls(const struct upstream_session *s) {
    return s->config->proto == UP_TLS;
}
#endif

static void tcp_disconnect(struct upstream_session *s, bool retry) {
#ifdef ENABLE_WOLFSSL
    if (s->u.tcp.ssl) {
        wolfSSL_free(s->u.tcp.ssl);
        s->u.tcp.ssl = NULL;
    }
    s->u.tcp.tls_want = 0;
    s->u.tcp.tls_read_want = 0;
    s->u.tcp.tls_write_want = 0;
#endif
    source_detach(&s->source);
    s->u.tcp.state = TCP_DOWN;
    tcp_reset_input(s);
    /* requests still bound to a query are resent on reconnect, like the Zig
     * version's send_list. an orphan — a lingering entry whose query was
     * answered elsewhere — is dropped instead: it was only kept so a late
     * reply on *this* connection could still match as a recovery signal, and
     * the connection is gone. resending it would be pure duplicate traffic,
     * and pointless besides: while a group is unhealthy every new query is
     * sent to the primary anyway, so fresh traffic already probes it. */
    struct tcp_request *req = s->u.tcp.head;
    while (req) {
        struct tcp_request *next = req->next;
        if (req->ref.query) {
            req->offset = 0;
            req->sent = false;
            req->write_started = false;
        } else {
            tcp_request_free(s, req);
        }
        req = next;
    }
    if (s->retired && !s->pending_count) return;
    if (retry && s->pending_count) s->retry_at = now_msec() + 250;
}

static bool tcp_start(struct upstream_session *s) {
    int fd = new_socket(socket_addr_family(&s->config->addr), SOCK_STREAM);
    if (fd < 0) {
        log_warning("socket(%s) failed: (%d) %s", s->config->url, errno, strerror(errno));
        s->retry_at = now_msec() + 1000;
        return false;
    }
    int rc = connect(fd, (struct sockaddr *)&s->config->addr.storage, s->config->addr.len);
    if (rc < 0 && errno != EINPROGRESS) {
        log_warning("connect(%s) failed: (%d) %s", s->config->url, errno, strerror(errno));
        close(fd);
        s->retry_at = now_msec() + 1000;
        return false;
    }
    if (!source_add(&s->source, fd, SOURCE_UPSTREAM_TCP,
        EPOLLIN | EPOLLOUT | EPOLLRDHUP)) {
        s->retry_at = now_msec() + 1000;
        return false;
    }
    s->u.tcp.state = TCP_CONNECTING;
    s->retry_at = 0;
    return true;
}

static void tcp_update_events(struct upstream_session *s) {
    u32 events = EPOLLRDHUP;
    if (s->u.tcp.state == TCP_CONNECTING) {
        events |= EPOLLOUT;
#ifdef ENABLE_WOLFSSL
    } else if (s->u.tcp.state == TCP_TLS_HANDSHAKE) {
        events |= s->u.tcp.tls_want;
#endif
    } else if (s->u.tcp.state == TCP_READY) {
#ifdef ENABLE_WOLFSSL
        if (session_is_tls(s)) events |= s->u.tcp.tls_read_want ? s->u.tcp.tls_read_want : EPOLLIN;
        else
#endif
            events |= EPOLLIN;
        for (struct tcp_request *req = s->u.tcp.head; req; req = req->next) {
            if (req->sent) continue;
#ifdef ENABLE_WOLFSSL
            if (session_is_tls(s)) events |= s->u.tcp.tls_write_want ? s->u.tcp.tls_write_want : EPOLLOUT;
            else
#endif
                events |= EPOLLOUT;
            break;
        }
    }
    source_mod(&s->source, events);
}

#ifdef ENABLE_WOLFSSL
static const char *tls_error_string(int error) {
    if (error == WOLFSSL_ERROR_SYSCALL) return strerror(errno);
    return wolfSSL_ERR_error_string((unsigned long)(unsigned int)error, NULL);
}

static bool tcp_tls_handshake(struct upstream_session *s) {
    int rc = wolfSSL_connect(s->u.tcp.ssl);
    if (rc == WOLFSSL_SUCCESS) {
        s->u.tcp.state = TCP_READY;
        s->u.tcp.tls_want = 0;
        log_verbose("%s | %s | %s", s->config->url,
            wolfSSL_get_version(s->u.tcp.ssl), wolfSSL_get_cipher(s->u.tcp.ssl));
        tcp_update_events(s);
        return true;
    }
    int error = wolfSSL_get_error(s->u.tcp.ssl, rc);
    if (error == WOLFSSL_ERROR_WANT_READ) s->u.tcp.tls_want = EPOLLIN;
    else if (error == WOLFSSL_ERROR_WANT_WRITE) s->u.tcp.tls_want = EPOLLOUT;
    else {
        log_warning("TLS handshake(%s) failed: %s", s->config->url, tls_error_string(error));
        tcp_disconnect(s, true);
        return false;
    }
    tcp_update_events(s);
    return false;
}

static bool tcp_tls_begin(struct upstream_session *s) {
    s->u.tcp.ssl = wolfSSL_new(tls_ctx);
    if (!s->u.tcp.ssl || wolfSSL_set_fd(s->u.tcp.ssl, s->source.fd) != WOLFSSL_SUCCESS) {
        log_warning("unable to create TLS connection for %s", s->config->url);
        tcp_disconnect(s, true);
        return false;
    }
    if (s->config->host) {
        size_t len = strlen(s->config->host);
        if (len > UINT16_MAX ||
            wolfSSL_UseSNI(s->u.tcp.ssl, WOLFSSL_SNI_HOST_NAME, s->config->host, (unsigned short)len) != WOLFSSL_SUCCESS ||
            (g_config.cert_verify && wolfSSL_check_domain_name(s->u.tcp.ssl, s->config->host) != WOLFSSL_SUCCESS)) {
            log_warning("unable to set TLS host for %s", s->config->url);
            tcp_disconnect(s, true);
            return false;
        }
    }
    wolfSSL_set_verify(s->u.tcp.ssl,
        g_config.cert_verify ? WOLFSSL_VERIFY_PEER : WOLFSSL_VERIFY_NONE, NULL);
    s->u.tcp.state = TCP_TLS_HANDSHAKE;
    s->u.tcp.tls_want = EPOLLOUT;
    return tcp_tls_handshake(s);
}
#endif

static bool tcp_finish_connect(struct upstream_session *s) {
    int error = 0;
    socklen_t len = sizeof(error);
    if (getsockopt(s->source.fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0 || error) {
        if (error) errno = error;
        log_warning("connect(%s) failed: (%d) %s", s->config->url, errno, strerror(errno));
        tcp_disconnect(s, true);
        return false;
    }
#ifdef ENABLE_WOLFSSL
    if (session_is_tls(s)) return tcp_tls_begin(s);
#endif
    s->u.tcp.state = TCP_READY;
    tcp_update_events(s);
    return true;
}

static ssize_t tcp_write_data(struct upstream_session *s, const void *data, size_t len) {
#ifdef ENABLE_WOLFSSL
    if (session_is_tls(s)) {
        int rc = wolfSSL_write(s->u.tcp.ssl, data, (int)min(len, (size_t)INT32_MAX));
        if (rc > 0) {
            s->u.tcp.tls_write_want = 0;
            return rc;
        }
        int error = wolfSSL_get_error(s->u.tcp.ssl, rc);
        if (error == WOLFSSL_ERROR_WANT_READ) s->u.tcp.tls_write_want = EPOLLIN;
        else if (error == WOLFSSL_ERROR_WANT_WRITE) s->u.tcp.tls_write_want = EPOLLOUT;
        else {
            log_warning("TLS write(%s) failed: %s", s->config->url, tls_error_string(error));
            return -2;
        }
        errno = EAGAIN;
        return -1;
    }
#endif
    return send(s->source.fd, data, len, MSG_NOSIGNAL);
}

static void tcp_session_write(struct upstream_session *s) {
    if (s->u.tcp.state == TCP_CONNECTING) {
        if (!tcp_finish_connect(s)) return;
    }
#ifdef ENABLE_WOLFSSL
    if (s->u.tcp.state == TCP_TLS_HANDSHAKE) {
        if (!tcp_tls_handshake(s)) return;
    }
#endif
    if (s->u.tcp.state != TCP_READY) return;
    for (struct tcp_request *req = s->u.tcp.head; req; req = req->next) {
        if (req->sent) continue;
        ssize_t n;
        req->write_started = true;
        do {
            n = tcp_write_data(s, req->frame + req->offset, req->frame_len - req->offset);
        } while (n == -1 && errno == EINTR);
        if (n > 0) {
            req->offset += (size_t)n;
            if (req->offset == req->frame_len) req->sent = true;
            else return;
        } else if (n == -2) {
            tcp_disconnect(s, true);
            return;
        } else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            tcp_update_events(s);
            return;
        } else {
            log_warning("send(%s) failed: (%d) %s", s->config->url, errno, strerror(errno));
            tcp_disconnect(s, true);
            return;
        }
    }
    tcp_update_events(s);
}

static ssize_t tcp_read_data(struct upstream_session *s, void *data, size_t len) {
#ifdef ENABLE_WOLFSSL
    if (session_is_tls(s)) {
        int rc = wolfSSL_read(s->u.tcp.ssl, data, (int)min(len, (size_t)INT32_MAX));
        if (rc > 0) {
            s->u.tcp.tls_read_want = 0;
            return rc;
        }
        int error = wolfSSL_get_error(s->u.tcp.ssl, rc);
        if (error == WOLFSSL_ERROR_ZERO_RETURN) return 0;
        if (error == WOLFSSL_ERROR_WANT_READ) s->u.tcp.tls_read_want = EPOLLIN;
        else if (error == WOLFSSL_ERROR_WANT_WRITE) s->u.tcp.tls_read_want = EPOLLOUT;
        else {
            log_warning("TLS read(%s) failed: %s", s->config->url, tls_error_string(error));
            return -2;
        }
        errno = EAGAIN;
        return -1;
    }
#endif
    return recv(s->source.fd, data, len, 0);
}

static bool tcp_read_bytes(struct upstream_session *s, void *buf, size_t *have, size_t need) {
    while (*have < need) {
        ssize_t n = tcp_read_data(s, (u8 *)buf + *have, need - *have);
        if (n > 0) *have += (size_t)n;
        else if (n == 0) { tcp_disconnect(s, true); return false; }
        else if (n == -2) { tcp_disconnect(s, true); return false; }
        else if (errno == EINTR) continue;
        else if (errno == EAGAIN || errno == EWOULDBLOCK) { tcp_update_events(s); return false; }
        else {
            log_warning("recv(%s) failed: (%d) %s", s->config->url, errno, strerror(errno));
            tcp_disconnect(s, true);
            return false;
        }
    }
    return true;
}

static void tcp_session_read(struct upstream_session *s) {
#ifdef ENABLE_WOLFSSL
    if (s->u.tcp.state == TCP_TLS_HANDSHAKE) {
        if (!tcp_tls_handshake(s)) return;
    }
#endif
    if (s->u.tcp.state != TCP_READY) return;
    while (!s->source.closed) {
        if (!tcp_read_bytes(s, s->u.tcp.len_buf, &s->u.tcp.len_have, 2)) return;
        if (!s->u.tcp.input) {
            u16 len = ((u16)s->u.tcp.len_buf[0] << 8) | s->u.tcp.len_buf[1];
            if (len < dns_header_len()) {
                log_warning("invalid TCP DNS length %u from %s", (uint)len, s->config->url);
                tcp_disconnect(s, true);
                return;
            }
            s->u.tcp.input = message_new(len);
            s->u.tcp.input->len = len;
        }
        if (!tcp_read_bytes(s, s->u.tcp.input->data, &s->u.tcp.input_have, s->u.tcp.input->len)) return;
        struct message *msg = s->u.tcp.input;
        s->u.tcp.input = NULL;
        s->u.tcp.input_have = 0;
        s->u.tcp.len_have = 0;
        upstream_on_reply(s, msg);
        message_unref(msg);
        if (s->retired && !s->pending_count) {
            source_detach(&s->source);
            return;
        }
    }
}

static bool udp_start(struct upstream_session *s) {
    int fd = new_socket(socket_addr_family(&s->config->addr), SOCK_DGRAM);
    if (fd < 0) {
        log_warning("socket(%s) failed: (%d) %s", s->config->url, errno, strerror(errno));
        s->retry_at = now_msec() + 1000;
        return false;
    }
    if (!source_add(&s->source, fd, SOURCE_UPSTREAM_UDP, EPOLLIN)) {
        s->retry_at = now_msec() + 1000;
        return false;
    }
    s->retry_at = 0;
    return true;
}

static struct upstream_session *session_new(struct upstream_config *config) {
#ifndef ENABLE_WOLFSSL
    if (config->proto == UP_TLS) {
        log_error("TLS upstream %s requires a build with WOLFSSL=1", config->url);
        exit(2);
    }
#endif
    struct upstream_session *s = xcalloc(1, sizeof(*s));
    s->source.fd = -1;
    s->source.closed = true;
    s->config = config;
    s->create_time = now_msec();
    s->tcp = config->proto == UP_RAW_TCP || config->proto == UP_TCP || config->proto == UP_TLS;
    s->next = sessions;
    sessions = s;
    config->runtime = s;
    if (s->tcp) {
        s->u.tcp.state = TCP_DOWN;
        tcp_start(s);
    } else {
        udp_start(s);
    }
    return s;
}

static struct upstream_session *session_get(struct upstream_config *config) {
    struct upstream_session *s = config->runtime;
    if (s && session_should_retire(s)) session_mark_retired(s);
    if (!config->runtime) s = session_new(config);
    else s = config->runtime;
    return s;
}

static void session_send(struct upstream_config *config, struct query *q, struct message *msg) {
    struct upstream_session *s = session_get(config);
    u16 qid = dns_get_id(msg->data);
    u64 now = now_msec();
    if (!s->tcp) {
        if (s->source.closed && (!s->retry_at || now >= s->retry_at))
            udp_start(s);
        if (s->source.closed) {
            ++s->query_count;
            return;
        }
        unsigned repeat = config->tag == TAG_GFW ? g_config.trustdns_packet_n : 1;
        bool any = false;
        for (unsigned i = 0; i < repeat; ++i) {
            ssize_t n = sendto(s->source.fd, msg->data, msg->len, 0,
                (struct sockaddr *)&config->addr.storage, config->addr.len);
            if (n == msg->len) any = true;
            else if (n < 0) log_warning("send(%s) failed: (%d) %s", config->url, errno, strerror(errno));
        }
        if (any) udp_pending_add(s, q, msg);
    } else {
        size_t frame_len = 2 + msg->len;
        struct tcp_request *req = xcalloc(1, sizeof(*req) + frame_len);
        req->qid = qid;
        req->frame_len = frame_len;
        req->expire_at = now + (u64)g_config.upstream_timeout * 1000;
        req->frame[0] = (u8)(msg->len >> 8);
        req->frame[1] = (u8)msg->len;
        memcpy(req->frame + 2, msg->data, msg->len);
        req->ref.session = s;
        req->ref.query = q;
        req->ref.qnamelen = q->qnamelen;
        req->ref.question = req->frame + 2 + dns_header_len();
        req->ref.q_next = q->refs;
        q->refs = &req->ref;
        req->prev = s->u.tcp.tail;
        if (s->u.tcp.tail) s->u.tcp.tail->next = req;
        else s->u.tcp.head = req;
        s->u.tcp.tail = req;
        ++s->pending_count;
        if (s->u.tcp.state == TCP_DOWN && !s->retry_at) tcp_start(s);
        if (!s->source.closed) tcp_update_events(s);
    }
    ++s->query_count;
}

/* [passive health-check] a good reply just arrived from a primary (non-fallback)
 * upstream of this group -> primaries are alive. clears the outstanding marker
 * and, if the group was unhealthy, switches back to primary-only. */
static void group_primary_alive(u8 tag) {
    struct group_config *group = &g_config.groups[tag];
    if (!group->fallback_enabled) return; /* health tracking is fallback-only */
    group->pending_since = 0;
    if (!group->primary_healthy) {
        group->primary_healthy = true;
        log_info("tag:%s primary upstream(s) recovered, stop querying ?fallback", tag_to_name(tag));
    }
}

static void send_group(u8 tag, struct query *q, struct message *msg, bool raw_udp) {
    struct group_config *group = &g_config.groups[tag];
    struct upstream_vec *vec = &group->upstreams;
    /* primary upstreams are always queried; fallback upstreams are queried too
     * only while the group is unhealthy (so they back up the primaries, while
     * the primaries' real replies keep flowing in to detect recovery) */
    bool send_fallback = !group->primary_healthy;
    bool sent_primary = false;
    for (size_t i = 0; i < vec->len; ++i) {
        struct upstream_config *config = &vec->items[i];
        if (config->fallback && !send_fallback) continue;
        if (config->proto == UP_RAW_UDP && !raw_udp) continue;
        if (config->proto == UP_RAW_TCP && raw_udp) continue;
        log_verbose("forward qid:%u to %s", (uint)dns_get_id(msg->data), config->url);
        session_send(config, q, msg);
        if (!config->fallback) sent_primary = true;
    }
    /* passive health-check: remember when the primary path has an outstanding
     * (so-far unanswered) query, so group_health_check can detect all-primary-down */
    if (group->fallback_enabled && sent_primary && !group->pending_since)
        group->pending_since = now_msec();
}

static void handle_query(struct message *msg, enum query_from from,
    struct listener *udp_listener, const struct socket_addr *peer, struct tcp_client *tcp_client) {
    char ascii[DNS_NAME_MAXLEN + 1];
    int qnamelen;
    if (!dns_check_query(msg->data, msg->len, ascii, &qnamelen)) {
        log_warning("invalid DNS query");
        send_bad_query_reply(msg, from, udp_listener, peer, tcp_client);
        return;
    }
    u16 original_id = dns_get_id(msg->data);
    u16 qtype = dns_get_qtype(msg->data, qnamelen);
    u8 tag = dnl_is_empty() ? g_config.default_tag :
        dnl_get_tag(ascii, dns_ascii_namelen(qnamelen), g_config.default_tag);
    u16 bufsz = from == QUERY_UDP ? dns_get_bufsz(msg->data, msg->len, qnamelen) : DNS_MSG_MAXSIZE;
    log_verbose("query id:%u tag:%s qtype:%u '%s'", (uint)ntohs(original_id), tag_to_name(tag), (uint)qtype, ascii);

    if ((qtype == DNS_TYPE_AAAA && config_ip6_filter_query(tag)) || config_qtype_filtered(qtype)) {
        msg->len = dns_empty_reply(msg->data, qnamelen);
        send_immediate(msg, qnamelen, original_id, bufsz, from, udp_listener, peer, tcp_client);
        return;
    }

    const void *answer;
    size_t answer_len;
    u16 answer_count;
    if (local_rr_find(msg->data, qnamelen, &answer, &answer_len, &answer_count)) {
        struct message *reply = message_new(dns_header_len() + dns_question_len(qnamelen) + answer_len);
        if (!reply) {
            log_warning("local reply for %s exceeds the DNS message size limit", ascii);
            msg->len = dns_empty_reply(msg->data, qnamelen);
            send_immediate(msg, qnamelen, original_id, bufsz, from, udp_listener, peer, tcp_client);
            return;
        }
        reply->len = reply->cap;
        dns_make_reply(reply->data, msg->data, qnamelen, answer, answer_len, answer_count);
        send_immediate(reply, qnamelen, original_id, bufsz, from, udp_listener, peer, tcp_client);
        message_unref(reply);
        return;
    }

    if (tag_is_null(tag)) {
        msg->len = dns_empty_reply(msg->data, qnamelen);
        send_immediate(msg, qnamelen, original_id, bufsz, from, udp_listener, peer, tcp_client);
        return;
    }

    bool raw_udp = from == QUERY_UDP;
    /* Neither response nor verdict keys include an ECS subnet. */
    bool cacheable = dns_ecs_status(msg->data, msg->len, qnamelen) == 0;
    i32 ttl, refresh_ttl;
    bool add_ip;
    struct message *cached = cacheable ?
        cache_get(msg->data, qnamelen, &ttl, &refresh_ttl, &add_ip) : NULL;
    if (cached) {
        if (add_ip && tag != TAG_NONE && (qtype == DNS_TYPE_A || qtype == DNS_TYPE_AAAA) && ip_addctx[tag])
            dns_add_ip(cached->data, cached->len, qnamelen, ip_addctx[tag]);
        send_immediate(cached, qnamelen, original_id, bufsz, from, udp_listener, peer, tcp_client);
        if (ttl > refresh_ttl) {
            message_unref(cached);
            return;
        }
        if (raw_udp && cached->len + 30 > DNS_EDNS_MINSIZE) raw_udp = false;
        from = QUERY_LOCAL;
        udp_listener = NULL;
        peer = NULL;
        tcp_client = NULL;
        message_unref(cached);
    }

    struct query *q = query_new(msg, qnamelen, qtype, tag, bufsz, from,
        udp_listener, peer, tcp_client);
    if (!q) return;
    q->cacheable = cacheable;
    if (tag == TAG_NONE) {
        bool is_china;
        if (cacheable && verdict_cache_get(msg->data, qnamelen, &is_china)) {
            q->verdict = is_china ? VERDICT_CHINA : VERDICT_NON_CHINA;
            send_group(is_china ? TAG_CHN : TAG_GFW, q, msg, raw_udp);
        } else {
            send_group(TAG_CHN, q, msg, raw_udp);
            send_group(TAG_GFW, q, msg, raw_udp);
        }
    } else {
        send_group(tag, q, msg, raw_udp);
    }
}

static bool use_china_reply(struct message *msg, int qnamelen, bool cacheable, int *test_result) {
    *test_result = dns_test_ip(msg->data, msg->len, qnamelen, ip_testctx);
    if (*test_result == DNS_TEST_IP_IS_CHINA_IP || *test_result == DNS_TEST_IP_NON_CHINA_IP) {
        bool china = *test_result == DNS_TEST_IP_IS_CHINA_IP;
        if (cacheable && dns_ecs_status(msg->data, msg->len, qnamelen) == 0)
            verdict_cache_add(msg->data, qnamelen, china);
        return china;
    }
    if (*test_result == DNS_TEST_IP_NO_IP_FOUND) return g_config.noip_as_chnip;
    return dns_is_tc(msg->data);
}

static void upstream_on_reply(struct upstream_session *session, struct message *reply) {
    char ascii[DNS_NAME_MAXLEN + 1];
    int qnamelen;
    u16 new_len;
    if (!dns_check_reply(reply->data, reply->len, ascii, &qnamelen, &new_len)) {
        log_warning("invalid DNS reply from %s", session->config->url);
        return;
    }
    reply->len = new_len;
    u16 qid = dns_get_id(reply->data);

    /* consume the pending entry only now, after the reply passed validation:
     * `matched` = the reply answers one of this session's outstanding queries */
    struct query *q = NULL;
    bool matched = session_pending_remove(session, qid, reply->data, qnamelen, &q);
    if (!matched) return;

    /* passive health-check: a good reply (rcode noerror/nxdomain, not truncated)
     * that actually answers one of this primary (non-fallback) upstream's
     * outstanding queries means the group's primaries are alive. gated on
     * `matched` (the upstream session's own pending ids), not on the global
     * query list: while unhealthy the fallback may have already answered &
     * removed the query, yet this "late" primary reply still matches the
     * primary session's pending id and is exactly the recovery signal,
     * whereas a duplicate / unsolicited / spoofed reply matches no pending id
     * and is ignored. */
    if (matched && !session->config->fallback && dns_is_good(reply->data))
        group_primary_alive(session->config->tag);

    if (!q) return;
    dns_set_id(reply->data, q->original_id);
    if (q->from != QUERY_UDP && dns_is_tc(reply->data)) return;

    u16 qtype = dns_get_qtype(reply->data, qnamelen);
    bool address_query = qtype == DNS_TYPE_A || qtype == DNS_TYPE_AAAA;
    int test_result = DNS_TEST_IP_OTHER_CASE;
    struct message *selected = reply;

    if (q->tag == TAG_NONE && address_query) {
        if (session->config->tag == TAG_CHN) {
            if (q->verdict == VERDICT_CHINA ||
                use_china_reply(reply, qnamelen, q->cacheable, &test_result)) {
                log_verbose("accept qid:%u from %s", (uint)qid, session->config->url);
            } else if (q->trust_reply) {
                selected = q->trust_reply;
            } else {
                q->verdict = VERDICT_NON_CHINA;
                return;
            }
        } else if (session->config->tag == TAG_GFW) {
            if (q->verdict != VERDICT_NON_CHINA) {
                if (!q->trust_reply) q->trust_reply = message_ref(reply);
                return;
            }
        }
    }

    if (qtype == DNS_TYPE_AAAA) {
        if (test_result == DNS_TEST_IP_OTHER_CASE &&
            (g_config.groups[q->tag].ip6.china_ip || g_config.groups[q->tag].ip6.non_china_ip))
            test_result = dns_test_ip(selected->data, selected->len, qnamelen, ip_testctx);
        if (config_ip6_filter_reply(q->tag, test_result))
            selected->len = dns_empty_reply(selected->data, qnamelen);
    }

    if (address_query && q->tag != TAG_NONE && ip_addctx[q->tag])
        dns_add_ip(selected->data, selected->len, qnamelen, ip_addctx[q->tag]);

    i32 ttl;
    if (q->cacheable) cache_add(selected->data, selected->len, qnamelen, &ttl);
    send_reply_to_query(q, selected);
    query_delete(q);
}

static void udp_listener_read(struct listener *listener) {
    for (;;) {
        struct message *msg = message_new(DNS_QMSG_MAXSIZE);
        struct socket_addr peer = { .len = sizeof(peer.storage) };
        ssize_t n = recvfrom(listener->source.fd, msg->data, msg->cap, 0,
            (struct sockaddr *)&peer.storage, &peer.len);
        if (n > 0) {
            msg->len = (u16)n;
            handle_query(msg, QUERY_UDP, listener, &peer, NULL);
            message_unref(msg);
        } else {
            message_unref(msg);
            if (n < 0 && errno == EINTR) continue;
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
            if (n < 0) log_warning("recvfrom listener failed: (%d) %s", errno, strerror(errno));
            return;
        }
    }
}

static void tcp_client_read(struct tcp_client *client) {
    for (;;) {
        ssize_t n = recv(client->source.fd, client->input + client->input_len,
            sizeof(client->input) - client->input_len, 0);
        if (n > 0) client->input_len += (size_t)n;
        else if (n == 0) { client_read_eof(client); return; }
        else if (errno == EINTR) continue;
        else if (errno == EAGAIN || errno == EWOULDBLOCK) break;
        else { client_close(client); return; }

        while (client->input_len >= 2) {
            u16 len = ((u16)client->input[0] << 8) | client->input[1];
            if (len < 1 || len > DNS_QMSG_MAXSIZE) {
                log_warning("invalid client TCP DNS length: %u", (uint)len);
                client_close(client);
                return;
            }
            if (client->input_len < (size_t)len + 2) break;
            struct message *msg = message_from(client->input + 2, len);
            handle_query(msg, QUERY_TCP, NULL, &client->peer, client);
            message_unref(msg);
            size_t used = (size_t)len + 2;
            memmove(client->input, client->input + used, client->input_len - used);
            client->input_len -= used;
        }
        if (client->input_len == sizeof(client->input)) {
            client_close(client);
            return;
        }
    }
}

static void tcp_listener_accept(struct listener *listener) {
    for (;;) {
        struct socket_addr peer = { .len = sizeof(peer.storage) };
        int fd = accept4(listener->source.fd, (struct sockaddr *)&peer.storage, &peer.len,
            SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd < 0 && errno == ENOSYS) {
            fd = accept(listener->source.fd, (struct sockaddr *)&peer.storage, &peer.len);
            if (fd >= 0 && (set_nonblocking(fd) < 0 || set_cloexec(fd) < 0)) {
                int error = errno;
                close(fd);
                fd = -1;
                errno = error;
            }
        }
        if (fd >= 0) {
            int one = 1;
            setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
            struct tcp_client *client = xcalloc(1, sizeof(*client));
            client->peer = peer;
            if (!source_add(&client->source, fd, SOURCE_TCP_CLIENT, EPOLLIN | EPOLLRDHUP)) {
                free(client);
                return;
            }
            client->next = clients;
            clients = client;
        } else if (errno == EINTR) {
            continue;
        } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return;
        } else {
            log_warning("accept failed: (%d) %s", errno, strerror(errno));
            return;
        }
    }
}

static struct listener *new_listener(const char *ip, u16 port, int type) {
    struct listener *listener = xcalloc(1, sizeof(*listener));
    if (!socket_addr_parse(&listener->addr, ip, port)) {
        free(listener);
        return NULL;
    }
    int fd = new_socket(socket_addr_family(&listener->addr), type);
    if (fd < 0) {
        free(listener);
        return NULL;
    }
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (g_config.reuse_port && setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one)) < 0) {
        log_error("SO_REUSEPORT failed: (%d) %s", errno, strerror(errno));
        close(fd);
        free(listener);
        return NULL;
    }
    if (bind(fd, (struct sockaddr *)&listener->addr.storage, listener->addr.len) < 0 ||
        (type == SOCK_STREAM && listen(fd, 1024) < 0)) {
        log_error("listen on %s#%u failed: (%d) %s", ip, (uint)port, errno, strerror(errno));
        close(fd);
        free(listener);
        return NULL;
    }
    snprintf(listener->ip, sizeof(listener->ip), "%s", ip);
    listener->port = port;
    if (!source_add(&listener->source, fd,
        type == SOCK_DGRAM ? SOURCE_UDP_LISTENER : SOURCE_TCP_LISTENER, EPOLLIN)) {
        free(listener);
        return NULL;
    }
    listener->next = listeners;
    listeners = listener;
    return listener;
}

static void signal_read(struct event_source *source) {
    struct signalfd_siginfo info;
    while (read(source->fd, &info, sizeof(info)) == sizeof(info)) {
        if (info.ssi_signo == SIGINT || info.ssi_signo == SIGTERM) {
            cache_dump(false);
            verdict_cache_dump(false);
            running = false;
        } else if (info.ssi_signo == SIGUSR1) {
            cache_dump(true);
            verdict_cache_dump(true);
        }
    }
}

static void init_signal_source(void) {
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGUSR1);
    if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) {
        log_error("sigprocmask failed: %s", strerror(errno));
        exit(1);
    }
    int fd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
    if (fd < 0) {
        log_error("signalfd failed: %s", strerror(errno));
        exit(1);
    }
    if (!source_add(&signal_source, fd, SOURCE_SIGNAL, EPOLLIN)) {
        exit(1);
    }
}

static void cleanup_pending(void) {
    u64 now = now_msec();
    while (!list_empty(&query_deadlines)) {
        struct query *q = container_of(query_deadlines.next, struct query, deadline);
        if (q->request_time + (u64)g_config.upstream_timeout * 1000 > now) break;
        log_verbose("query qid:%u timeout", (uint)q->qid);
        query_delete(q);
    }
    /* entries bound to a live query were just released by the query_delete
     * calls above, so all that is left here is ageing out the orphans that a
     * session serving the passive health-check keeps (a late reply must still
     * be recognizable as a primary-recovery signal). entries are in send
     * order, so `expire_at` grows along the list and the orphans due for
     * purging are a prefix of it — the scan stops at the first entry that is
     * still within its window instead of walking the whole list. */
    for (struct upstream_session *s = sessions; s; s = s->next) {
        u64 oldest = 0; /* earliest expire_at still to come; 0 = nothing left */
        if (!s->tcp) {
            struct pending_id *id = s->u.udp.head;
            while (id) {
                struct pending_id *next = id->next;
                if (now < id->expire_at) { oldest = id->expire_at; break; }
                /* a live entry can only be expired if its query outlived its
                 * own deadline, which the loop above rules out; keep it */
                if (!id->ref.query) udp_pending_free(s, id);
                id = next;
            }
            if (s->retired && !s->pending_count) source_detach(&s->source);
        } else {
            struct tcp_request *req = s->u.tcp.head;
            while (req) {
                struct tcp_request *next = req->next;
                if (now < req->expire_at) { oldest = req->expire_at; break; }
                if (!req->ref.query) tcp_request_free(s, req);
                req = next;
            }
            if (s->retired && !s->pending_count) {
                source_detach(&s->source);
            } else if (s->u.tcp.state == TCP_DOWN && s->pending_count &&
                s->retry_at && now >= s->retry_at) {
                tcp_start(s);
            }
        }
        /* only a linger session can hold an entry past its query's deadline,
         * so only it needs a wakeup of its own */
        s->oldest_linger_at = session_needs_linger(s) ? oldest : 0;
    }
}

static void sessions_sweep(void) {
    struct upstream_session **p = &sessions;
    while (*p) {
        struct upstream_session *s = *p;
        if (!s->source.closed || s->pending_count || !s->retired) {
            p = &s->next;
            continue;
        }
        *p = s->next;
        if (s->config->runtime == s) s->config->runtime = NULL;
        if (s->tcp) {
#ifdef ENABLE_WOLFSSL
            if (s->u.tcp.ssl) wolfSSL_free(s->u.tcp.ssl);
#endif
            tcp_reset_input(s);
        }
        free(s);
    }
}

/* [passive health-check] flip a group to unhealthy once its primary upstreams
 * have stayed unanswered for `timeout-sec`, so queries also go to ?fallback */
static void group_health_check(void) {
    u64 timeout_ms = (u64)g_config.upstream_timeout * 1000;
    u64 now = now_msec();
    for (u8 tag = 0; tag <= TAG__MAX; ++tag) {
        struct group_config *group = &g_config.groups[tag];
        if (!group->fallback_enabled || !group->primary_healthy || !group->pending_since)
            continue;
        if (now >= group->pending_since + timeout_ms) {
            group->primary_healthy = false;
            log_warning("tag:%s primary upstream(s) unresponsive, also querying ?fallback",
                tag_to_name(tag));
        }
    }
}

static int next_timeout(void) {
    u64 now = now_msec();
    u64 deadline = UINT64_MAX;
    if (!list_empty(&query_deadlines)) {
        struct query *q = container_of(query_deadlines.next, struct query, deadline);
        deadline = q->request_time + (u64)g_config.upstream_timeout * 1000;
    }
    for (struct upstream_session *s = sessions; s; s = s->next) {
        if (s->tcp && s->u.tcp.state == TCP_DOWN && s->pending_count && s->retry_at && s->retry_at < deadline)
            deadline = s->retry_at;
        /* wake up to age out lingering session entries (cleanup_pending keeps
         * this field fresh; 0 means nothing is lingering) */
        if (s->oldest_linger_at && s->oldest_linger_at < deadline)
            deadline = s->oldest_linger_at;
    }
    /* keep the epoll wait in sync with the passive health-check deadline */
    u64 timeout_ms = (u64)g_config.upstream_timeout * 1000;
    for (u8 tag = 0; tag <= TAG__MAX; ++tag) {
        struct group_config *group = &g_config.groups[tag];
        if (group->fallback_enabled && group->primary_healthy && group->pending_since &&
            group->pending_since + timeout_ms < deadline)
            deadline = group->pending_since + timeout_ms;
    }
    if (deadline == UINT64_MAX) return -1;
    if (deadline <= now) return 0;
    u64 delay = deadline - now;
    return delay > INT32_MAX ? INT32_MAX : (int)delay;
}

#ifdef ENABLE_WOLFSSL
static void tls_init(void) {
    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        log_error("wolfSSL initialization failed");
        exit(1);
    }
    tls_ctx = wolfSSL_CTX_new(wolfTLS_client_method());
    if (!tls_ctx || wolfSSL_CTX_SetMinVersion(tls_ctx, WOLFSSL_TLSV1_2) != WOLFSSL_SUCCESS) {
        log_error("unable to create wolfSSL client context");
        exit(1);
    }
    const char *chacha = "TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305";
    const char *aes = "TLS_AES_128_GCM_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256";
    char ciphers[256];
    snprintf(ciphers, sizeof(ciphers), "%s:%s", has_aes() ? aes : chacha, has_aes() ? chacha : aes);
    if (wolfSSL_CTX_set_cipher_list(tls_ctx, ciphers) != WOLFSSL_SUCCESS) {
        log_error("unable to configure wolfSSL cipher list");
        exit(1);
    }
    long options = WOLFSSL_OP_NO_COMPRESSION;
#if LIBWOLFSSL_VERSION_HEX >= 0x05006006
    options |= WOLFSSL_OP_NO_RENEGOTIATION;
#endif
    wolfSSL_CTX_set_options(tls_ctx, options);
    if (!g_config.cert_verify) return;
    int ok;
    if (g_config.ca_certs) {
        ok = is_dir(g_config.ca_certs) ?
            wolfSSL_CTX_load_verify_locations(tls_ctx, NULL, g_config.ca_certs) :
            wolfSSL_CTX_load_verify_locations(tls_ctx, g_config.ca_certs, NULL);
    } else {
        ok = wolfSSL_CTX_load_system_CA_certs(tls_ctx);
    }
    if (ok != WOLFSSL_SUCCESS) {
        log_error("unable to load CA certificates%s%s", g_config.ca_certs ? ": " : "",
            g_config.ca_certs ? g_config.ca_certs : "");
        exit(1);
    }
}
#endif

void server_init(void) {
    list_init(&query_deadlines);
    query_bucket_count = QUERY_INITIAL_BUCKETS;
    query_buckets = xcalloc(query_bucket_count, sizeof(*query_buckets));
    epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd < 0) {
        log_error("epoll_create1 failed: (%d) %s", errno, strerror(errno));
        exit(1);
    }
    bool need_ip_test = g_config.default_tag == TAG_NONE;
#ifdef ENABLE_WOLFSSL
    bool has_tls = false;
    for (u8 tag = 0; tag <= TAG_NONE; ++tag)
        for (size_t i = 0; i < g_config.groups[tag].upstreams.len; ++i)
            if (g_config.groups[tag].upstreams.items[i].proto == UP_TLS) has_tls = true;
    if (has_tls) tls_init();
#endif
    for (u8 tag = 0; tag <= TAG_NONE; ++tag) {
        struct group_config *group = &g_config.groups[tag];
        if (tag_is_null(tag)) continue;
        if (group->ip6.china_ip != group->ip6.non_china_ip) need_ip_test = true;
        if (tag != TAG_NONE && group->ipset_name46 && *group->ipset_name46) {
            ip_addctx[tag] = ipset_new_addctx(group->ipset_name46);
            log_info("tag:%s add IP to: %s", tag_to_name(tag), group->ipset_name46);
        }
        for (size_t i = 0; i < group->upstreams.len; ++i) {
#ifndef ENABLE_WOLFSSL
            if (group->upstreams.items[i].proto == UP_TLS) {
                log_error("TLS upstream %s requires a build with WOLFSSL=1",
                    group->upstreams.items[i].url);
                exit(2);
            }
#endif
            log_info("tag:%s upstream: %s", tag_to_name(tag), group->upstreams.items[i].url);
        }
        if (group->fallback_enabled)
            log_info("tag:%s ?fallback upstream(s): passive health-check enabled",
                tag_to_name(tag));
    }
    if (need_ip_test) {
        size_t len = strlen(g_config.chnroute_name) + strlen(g_config.chnroute6_name) + 2;
        char *name46 = xmalloc(len);
        snprintf(name46, len, "%s,%s", g_config.chnroute_name, g_config.chnroute6_name);
        ip_testctx = ipset_new_testctx(name46);
        log_info("IP test database: %s", name46);
        free(name46);
    }
    for (size_t i = 0; i < g_config.bind_ips.len; ++i) {
        for (size_t j = 0; j < g_config.bind_ports.len; ++j) {
            struct bind_port *port = &g_config.bind_ports.items[j];
            if (port->udp && !new_listener(g_config.bind_ips.items[i], port->port, SOCK_DGRAM)) exit(1);
            if (port->tcp && !new_listener(g_config.bind_ips.items[i], port->port, SOCK_STREAM)) exit(1);
            log_info("local listen address: %s#%u%s", g_config.bind_ips.items[i], (uint)port->port,
                port->tcp && port->udp ? "" : port->tcp ? "@tcp" : "@udp");
        }
    }
    init_signal_source();
}

void server_run(void) {
    struct epoll_event events[MAX_EVENTS];
    while (running) {
        int count = epoll_wait(epoll_fd, events, MAX_EVENTS, next_timeout());
        if (count < 0) {
            if (errno == EINTR) continue;
            log_error("epoll_wait failed: (%d) %s", errno, strerror(errno));
            break;
        }
        for (int i = 0; i < count; ++i) {
            struct event_source *source = events[i].data.ptr;
            u32 flags = events[i].events;
            if (source->closed) continue;
            switch (source->kind) {
                case SOURCE_UDP_LISTENER:
                    if (flags & EPOLLIN) udp_listener_read(container_of(source, struct listener, source));
                    break;
                case SOURCE_TCP_LISTENER:
                    if (flags & EPOLLIN) tcp_listener_accept(container_of(source, struct listener, source));
                    break;
                case SOURCE_TCP_CLIENT: {
                    struct tcp_client *client = container_of(source, struct tcp_client, source);
                    if (flags & (EPOLLERR | EPOLLHUP)) {
                        client_close(client);
                        break;
                    }
                    if (flags & EPOLLIN) tcp_client_read(client);
                    if (!source->closed && flags & EPOLLRDHUP) client_read_eof(client);
                    if (!source->closed && flags & EPOLLOUT) client_write(client);
                    break;
                }
                case SOURCE_UPSTREAM_UDP:
                    if (flags & EPOLLIN) udp_session_read(container_of(source, struct upstream_session, source));
                    break;
                case SOURCE_UPSTREAM_TCP: {
                    struct upstream_session *s = container_of(source, struct upstream_session, source);
                    bool terminal = flags & (EPOLLERR | EPOLLHUP | EPOLLRDHUP);
                    bool write_ready = flags & EPOLLOUT;
                    bool read_ready = flags & EPOLLIN;
#ifdef ENABLE_WOLFSSL
                    if (session_is_tls(s) && s->u.tcp.state == TCP_READY) {
                        if (s->u.tcp.tls_write_want && (flags & s->u.tcp.tls_write_want)) write_ready = true;
                        if (s->u.tcp.tls_read_want && (flags & s->u.tcp.tls_read_want)) read_ready = true;
                    }
#endif
                    if (write_ready) tcp_session_write(s);
                    if (!source->closed && read_ready) tcp_session_read(s);
                    if (!source->closed && terminal) tcp_disconnect(s, true);
                    break;
                }
                case SOURCE_SIGNAL:
                    if (flags & EPOLLIN) signal_read(source);
                    break;
            }
        }
        cleanup_pending();
        group_health_check();
        clients_sweep();
        sessions_sweep();
    }
}
