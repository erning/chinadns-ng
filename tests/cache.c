#define time test_time
#include "../src/cache.c"
#undef time
#include <assert.h>
#include <unistd.h>

static time_t current_time = 100;

time_t test_time(time_t *result) {
    if (result) *result = current_time;
    return current_time;
}

static void check_verdict_case(void) {
    u8 lower[] = { 0,1,1,0,0,1,0,0,0,0,0,0,1,'a',0,0,1,0,1 };
    u8 upper[sizeof(lower)];
    memcpy(upper, lower, sizeof(lower));
    upper[13] = 'A';
    bool is_china;
    verdict_cache_add(lower, 3, true);
    assert(verdict_cache_get(upper, 3, &is_china) && is_china);
    verdict_cache_add(upper, 3, false);
    assert(verdict_cache_get(lower, 3, &is_china) && !is_china);
    assert(verdict_count == 1);
    assert(!dns_name_equal("\xc1", "\xe1", 1));
}

static void check_stale_boundaries(void) {
    u8 reply[] = {
        0,1,0x81,0x80,0,1,0,1,0,0,0,0,1,'a',0,0,1,0,1,
        0xc0,0x0c,0,1,0,1,0,0,0,1,0,4,192,0,2,1,
    };
    g_config.cache_stale = 60;
    i32 ttl, refresh;
    bool add_ip;
    struct message *cached = message_new(CACHE_MSG_MAXSIZE);
    assert(cache_add(reply, sizeof(reply), 3, &ttl) && ttl == 1);
    const time_t times[] = {100, 101, 102, 161};
    for (size_t i = 0; i < array_n(times); ++i) {
        current_time = times[i];
        assert(cache_get(reply, 3, cached, &ttl, &refresh, &add_ip));
        assert(ttl == 101 - current_time);
        assert(dns_get_ttl(cached->data, cached->len, 3, 0, 0, 0) == 1);
    }
    current_time = 162;
    assert(!cache_get(reply, 3, cached, &ttl, &refresh, &add_ip));
    assert(!cache_count);

    /* Dumping and restoring at TTL zero must preserve the stale entry too. */
    current_time = 200;
    assert(cache_add(reply, sizeof(reply), 3, &ttl));
    current_time = 201;
    char path[] = "/tmp/chinadns-cache-test-XXXXXX";
    int fd = mkstemp(path);
    assert(fd >= 0);
    close(fd);
    g_config.cache_db = path;
    cache_dump(false);
    cache_remove(container_of(cache_lru.next, struct cache_entry, lru));
    cache_load();
    assert(cache_count == 1);
    assert(cache_get(reply, 3, cached, &ttl, &refresh, &add_ip) && ttl == 0);
    unlink(path);
    g_config.cache_db = NULL;

    g_config.cache_stale = 0;
    assert(!cache_get(reply, 3, cached, &ttl, &refresh, &add_ip));
    assert(!cache_count);
    g_config.cache_stale = 60;
    reply[28] = 0; /* An upstream TTL of zero is still not cacheable. */
    assert(!cache_add(reply, sizeof(reply), 3, &ttl));
    message_unref(cached);
}

static void check_size_limit(void) {
    static u8 reply[CACHE_MSG_MAXSIZE + 1];
    const u8 head[] = {
        0,1,0x81,0x80,0,1,0,1,0,0,0,0,1,'b',0,0,16,0,1,
        0xc0,0x0c,0,16,0,1,0,0,0,60,
    };
    i32 ttl;
    memcpy(reply, head, sizeof(head));
    for (size_t len = CACHE_MSG_MAXSIZE; len <= CACHE_MSG_MAXSIZE + 1; ++len) {
        u16 rdlen = (u16)(len - sizeof(head) - 2);
        reply[sizeof(head)] = (u8)(rdlen >> 8);
        reply[sizeof(head) + 1] = (u8)rdlen;
        assert(cache_add(reply, len, 3, &ttl) == (len == CACHE_MSG_MAXSIZE));
    }
}

int main(void) {
    g_config.cache_size = 8;
    g_config.verdict_cache_size = 8;
    cache_init();
    check_verdict_case();
    check_stale_boundaries();
    check_size_limit();
    puts("cache: case-insensitive verdicts, stale boundaries, size limit: PASS");
    return 0;
}
