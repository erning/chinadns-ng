/* Inject short writes without relying on socket buffer sizes or timing. */
#define send test_send
#define epoll_ctl test_epoll_ctl
#define dns_test_ip test_dns_test_ip
#include "../src/server.c"
#undef send
#undef epoll_ctl
#undef dns_test_ip

static u8 output[1024];
static size_t output_len;
static ssize_t first_write;
static bool first_call;

int test_dns_test_ip(const void *msg, ssize_t len, int qnamelen, const struct ipset_testctx *ctx) {
    (void)msg; (void)len; (void)qnamelen; (void)ctx;
    return DNS_TEST_IP_IS_CHINA_IP;
}

int test_epoll_ctl(int fd, int op, int target, struct epoll_event *event) {
    (void)fd; (void)op; (void)target; (void)event;
    return 0;
}

ssize_t test_send(int fd, const void *data, size_t len, int flags) {
    (void)fd; (void)flags;
    ssize_t n = (ssize_t)len;
    if (first_call) {
        first_call = false;
        n = first_write;
    }
    if (n < 0) { errno = EAGAIN; return -1; }
    assert((size_t)n <= len && output_len + (size_t)n <= sizeof(output));
    memcpy(output + output_len, data, (size_t)n);
    output_len += (size_t)n;
    return n;
}

static void check_cancel(bool linger, ssize_t short_write, bool start_write) {
    g_config.groups[TAG_CHN].fallback_enabled = linger;
    struct upstream_config config = { .proto = UP_TCP, .tag = TAG_CHN };
    struct upstream_session session = {
        .config = &config, .tcp = true, .source = { .fd = -1 },
    };
    session.u.tcp.state = TCP_READY;
    config.runtime = &session;
    u8 data[] = { 0,1,1,0,0,1,0,0,0,0,0,0,1,'a',0,0,1,0,1 };
    struct message *msg = message_from(data, sizeof(data));
    struct query first = { .qid = 1, .qnamelen = 3 };
    struct query second = { .qid = 2, .qnamelen = 3 };
    session_send(&config, &first, msg);
    dns_set_id(msg->data, second.qid);
    session_send(&config, &second, msg);

    output_len = 0;
    first_call = true;
    first_write = short_write;
    if (start_write) {
        tcp_session_write(&session);
        assert(!session.u.tcp.head->sent);
        assert(session.u.tcp.head->offset == (size_t)max(short_write, 0));
    }
    query_release_refs(&first);
    assert(!first.refs);
    assert(session.pending_count == 1);
    assert(session.u.tcp.head == session.u.tcp.tail);
    assert(session.u.tcp.head->ref.query == &second);
    assert(session.source.closed == start_write);

    if (start_write) {
        assert(session.u.tcp.state == TCP_DOWN && session.retry_at);
        assert(!session.u.tcp.head->offset && !session.u.tcp.head->write_started);
        /* A fresh connection must start at the second request's length prefix. */
        session.source.closed = false;
        session.u.tcp.state = TCP_READY;
    }
    first_call = false;
    output_len = 0;
    tcp_session_write(&session);
    assert(output_len == 2U + msg->len);
    assert(output[0] == 0 && output[1] == msg->len);
    assert(memcmp(output + 2, msg->data, msg->len) == 0);
    query_release_refs(&second);
    tcp_disconnect(&session, false);
    assert(!session.pending_count && !second.refs);
    message_unref(msg);
}

static void check_ecs_verdict(void) {
    g_config.verdict_cache_size = 8;
    cache_init();
    local_rr_init();
    u8 data[] = {
        0,1,0x81,0x80,0,1,0,1,0,0,0,1,1,'a',0,0,1,0,1,
        0xc0,0x0c,0,1,0,1,0,0,0,60,0,4,192,0,2,1,
        0,0,41,4,0xd0,0,0,0,0,0,11,0,8,0,7,0,1,24,24,192,0,2,
    };
    struct message *msg = message_from(data, sizeof(data));
    bool is_china;
    int result;
    assert(dns_ecs_status(msg->data, msg->len, 3) == 1);
    assert(dns_ecs_status(msg->data, msg->len - 1, 3) == -1);
    assert(use_china_reply(msg, 3, true, &result));
    assert(!verdict_cache_get(msg->data, 3, &is_china));
    msg->len = 35;
    msg->data[11] = 0;
    assert(use_china_reply(msg, 3, false, &result));
    assert(!verdict_cache_get(msg->data, 3, &is_china));
    assert(use_china_reply(msg, 3, true, &result));
    assert(verdict_cache_get(msg->data, 3, &is_china) && is_china);

    struct upstream_config config[2] = {
        { .proto = UP_TCP, .tag = TAG_CHN }, { .proto = UP_TCP, .tag = TAG_GFW },
    };
    struct upstream_session session[2] = {0};
    for (size_t i = 0; i < 2; ++i) {
        session[i].config = &config[i];
        session[i].tcp = true;
        session[i].source.fd = -1;
        session[i].u.tcp.state = TCP_READY;
        config[i].runtime = &session[i];
        struct group_config *group = &g_config.groups[config[i].tag];
        group->upstreams = (struct upstream_vec){ .items = &config[i], .len = 1 };
        group->fallback_enabled = false;
    }
    g_config.default_tag = TAG_NONE;
    list_init(&query_deadlines);
    query_bucket_count = QUERY_INITIAL_BUCKETS;
    query_buckets = xcalloc(query_bucket_count, sizeof(*query_buckets));
    msg->data[2] = 1;
    msg->data[3] = 0;
    msg->data[7] = 0;
    /* Turn the reply into a query and move its OPT past the question. */
    memcpy(msg->data + 19, data + 35, sizeof(data) - 35);
    msg->data[37] = 0; /* query ECS scope */
    for (int ecs = 0; ecs <= 1; ++ecs) {
        msg->len = ecs ? sizeof(data) - 16 : 19;
        msg->data[11] = (u8)ecs;
        handle_query(msg, QUERY_LOCAL, NULL, NULL, NULL);
        assert(session[0].pending_count == 1);
        assert(session[1].pending_count == (unsigned)ecs);
        struct query *q = query_find(dns_get_id(msg->data));
        assert(q && q->cacheable == !ecs);
        query_delete(q);
    }
    free(query_buckets);
    query_buckets = NULL;
    message_unref(msg);
}

int main(void) {
    for (int linger = 0; linger <= 1; ++linger) {
        check_cancel(linger, 3, true);
        check_cancel(linger, -1, true);
        check_cancel(linger, 0, false);
    }
    check_ecs_verdict();
    puts("server: canceled writes and ECS verdict isolation: PASS");
    return 0;
}
