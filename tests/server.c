/* Inject short writes without relying on socket buffer sizes or timing. */
#define send test_send
#define epoll_ctl test_epoll_ctl
#include "../src/server.c"
#undef send
#undef epoll_ctl

static u8 output[1024];
static size_t output_len;
static ssize_t first_write;
static bool first_call;

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

int main(void) {
    for (int linger = 0; linger <= 1; ++linger) {
        check_cancel(linger, 3, true);
        check_cancel(linger, -1, true);
        check_cancel(linger, 0, false);
    }
    puts("server: canceled partial and unsent requests: PASS");
    return 0;
}
