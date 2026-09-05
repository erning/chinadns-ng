#define _GNU_SOURCE
#include "cache.h"
#include "config.h"
#include "dns.h"
#include "log.h"
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define CACHE_MIN_BUCKETS 256

struct cache_entry {
    struct cache_entry *hash_next;
    struct list_node lru;
    time_t update_time;
    u32 hash;
    i32 ttl;
    i32 refresh_ttl;
    u16 msg_len;
    u8 qnamelen;
    bool added_ip;
    u8 msg[];
};

struct cache_db_header {
    i64 update_time;
    u32 hash;
    i32 ttl;
    i32 refresh_ttl;
    u16 msg_len;
    u8 qnamelen;
    u8 reserved;
};

STATIC_ASSERT(sizeof(struct cache_db_header) == 24);

struct ignored_domain {
    struct ignored_domain *next;
    u16 len;
    u8 wire[];
};

static struct cache_entry **cache_buckets;
static size_t cache_bucket_count;
static struct list_node cache_lru;
static size_t cache_count;
static struct ignored_domain *ignored_domains;

struct verdict_entry {
    struct verdict_entry *hash_next;
    struct list_node fifo;
    u32 hash;
    u16 name_len;
    bool is_china;
    u8 name[];
};

static struct verdict_entry **verdict_buckets;
static size_t verdict_bucket_count;
static struct list_node verdict_fifo;
static size_t verdict_count;

static const u8 *question_ptr(const void *msg) {
    return (const u8 *)msg + dns_header_len();
}

static size_t question_len(int qnamelen) {
    return dns_question_len(qnamelen);
}

static size_t bucket_count_for(size_t capacity) {
    size_t count = CACHE_MIN_BUCKETS;
    while (count < capacity) count *= 2;
    return count;
}

static struct cache_entry *cache_find(const void *query, int qnamelen, u32 hash) {
    const u8 *question = question_ptr(query);
    size_t len = question_len(qnamelen);
    for (struct cache_entry *e = cache_buckets[hash & (cache_bucket_count - 1)]; e; e = e->hash_next) {
        if (e->hash == hash && question_len(e->qnamelen) == len &&
            dns_question_equal(question_ptr(e->msg), question, qnamelen))
            return e;
    }
    return NULL;
}

static void cache_unlink_hash(struct cache_entry *entry) {
    size_t idx = entry->hash & (cache_bucket_count - 1);
    struct cache_entry **p = &cache_buckets[idx];
    while (*p && *p != entry) p = &(*p)->hash_next;
    if (*p) *p = entry->hash_next;
}

static void cache_remove(struct cache_entry *entry) {
    cache_unlink_hash(entry);
    list_remove(&entry->lru);
    free(entry);
    --cache_count;
}

static bool cache_ignored(const void *msg, int qnamelen) {
    const u8 *name = question_ptr(msg);
    const u8 *end = name + qnamelen - 1;
    for (const u8 *domain = name; domain < end; domain += 1 + *domain) {
        for (struct ignored_domain *item = ignored_domains; item; item = item->next) {
            size_t len = (size_t)(end - domain);
            if (item->len == len && dns_name_equal(item->wire, domain, len))
                return true;
        }
        if (*domain == 0 || *domain > DNS_NAME_LABEL_MAXLEN) break;
    }
    return false;
}

static void add_ignored_domain(const char *ascii) {
    u8 wire[DNS_NAME_WIRE_MAXLEN];
    u8 level = 0;
    size_t len = dns_ascii_to_wire(ascii, strlen(ascii), (char *)wire, &level);
    if (len <= 1 || level > 8) {
        log_error("invalid --cache-ignore domain: %s", ascii);
        exit(2);
    }
    --len;
    struct ignored_domain *item = xmalloc(sizeof(*item) + len);
    item->len = (u16)len;
    memcpy(item->wire, wire, len);
    item->next = ignored_domains;
    ignored_domains = item;
}

static bool ttl_usable(i32 ttl) {
    return ttl > 0 || (g_config.cache_stale && ttl < 0 && (u32)-ttl <= g_config.cache_stale);
}

struct message *cache_get(const void *query, int qnamelen,
    i32 *ttl, i32 *refresh_ttl, bool *add_ip) {
    if (!g_config.cache_size) return NULL;
    size_t len = question_len(qnamelen);
    u32 hash = dns_question_hash(question_ptr(query), qnamelen);
    struct cache_entry *e = cache_find(query, qnamelen, hash);
    if (!e) return NULL;
    time_t now = time(NULL);
    i64 elapsed64 = now > e->update_time ? (i64)(now - e->update_time) : 0;
    i32 elapsed = elapsed64 > INT32_MAX ? INT32_MAX : (i32)elapsed64;
    *ttl = e->ttl - elapsed;
    *refresh_ttl = e->refresh_ttl;
    if (!ttl_usable(*ttl)) {
        cache_remove(e);
        return NULL;
    }
    *add_ip = !e->added_ip;
    e->added_ip = true;
    list_remove(&e->lru);
    list_insert_after(&cache_lru, &e->lru);
    struct message *copy = message_from(e->msg, e->msg_len);
    memcpy(copy->data + dns_header_len(), question_ptr(query), len);
    if (elapsed) dns_update_ttl(copy->data, copy->len, e->qnamelen, -elapsed);
    return copy;
}

bool cache_add(void *reply, size_t len, int qnamelen, i32 *ttl) {
    if (!g_config.cache_size || !dns_is_good(reply) || cache_ignored(reply, qnamelen)) return false;
    if (dns_ecs_status(reply, (ssize_t)len, qnamelen) != 0) return false;
    i32 value = dns_get_ttl(reply, (ssize_t)len, qnamelen,
        g_config.cache_nodata_ttl, g_config.cache_min_ttl, g_config.cache_max_ttl);
    if (value <= 0) return false;
    *ttl = value;
    u32 hash = dns_question_hash(question_ptr(reply), qnamelen);
    struct cache_entry *old = cache_find(reply, qnamelen, hash);
    if (old) {
        i32 old_ttl = old->ttl - (i32)max((time_t)0, time(NULL) - old->update_time);
        if (abs(value - old_ttl) <= 2) return false;
        cache_remove(old);
    }
    while (cache_count >= g_config.cache_size && !list_empty(&cache_lru))
        cache_remove(container_of(cache_lru.prev, struct cache_entry, lru));
    if (len > UINT16_MAX || qnamelen > UINT8_MAX) return false;
    struct cache_entry *e = xmalloc(sizeof(*e) + len);
    e->update_time = time(NULL);
    e->hash = hash;
    e->ttl = value;
    i64 refresh_ttl = (i64)value * g_config.cache_refresh / 100;
    e->refresh_ttl = refresh_ttl > INT32_MAX ? INT32_MAX : (i32)refresh_ttl;
    e->msg_len = (u16)len;
    e->qnamelen = (u8)qnamelen;
    e->added_ip = true;
    memcpy(e->msg, reply, len);
    size_t idx = hash & (cache_bucket_count - 1);
    e->hash_next = cache_buckets[idx];
    cache_buckets[idx] = e;
    list_insert_after(&cache_lru, &e->lru);
    ++cache_count;
    return true;
}

static void cache_load(void) {
    if (!g_config.cache_size || !g_config.cache_db) return;
    FILE *file = fopen(g_config.cache_db, "rb");
    if (!file) {
        if (errno != ENOENT) log_warning("failed to open cache db %s: %s", g_config.cache_db, strerror(errno));
        return;
    }
    while (cache_count < g_config.cache_size) {
        struct cache_db_header h;
        if (fread(&h, sizeof(h), 1, file) != 1) break;
        size_t question_end = dns_header_len() + question_len(h.qnamelen);
        if (h.msg_len < DNS_MSG_MINSIZE ||
            h.qnamelen < DNS_NAME_WIRE_MINLEN ||
            question_end > h.msg_len) {
            log_warning("invalid entry in cache db %s", g_config.cache_db);
            break;
        }
        struct cache_entry *e = xmalloc(sizeof(*e) + h.msg_len);
        if (fread(e->msg, h.msg_len, 1, file) != 1) { free(e); break; }
        e->update_time = (time_t)h.update_time;
        /* Rehash old databases whose mixed-case questions used raw hashes. */
        e->hash = dns_question_hash(question_ptr(e->msg), h.qnamelen);
        e->ttl = h.ttl;
        e->refresh_ttl = h.refresh_ttl;
        e->msg_len = h.msg_len;
        e->qnamelen = h.qnamelen;
        e->added_ip = false;
        i32 remain = e->ttl - (i32)max((time_t)0, time(NULL) - e->update_time);
        if (!ttl_usable(remain)) { free(e); continue; }
        size_t idx = e->hash & (cache_bucket_count - 1);
        e->hash_next = cache_buckets[idx];
        cache_buckets[idx] = e;
        list_insert_before(&cache_lru, &e->lru);
        ++cache_count;
    }
    fclose(file);
    log_info("%zu entries from %s", cache_count, g_config.cache_db);
}

void cache_dump(bool manual) {
    if (!g_config.cache_size) return;
    const char *path = g_config.cache_db;
    if (!path && manual) path = "/tmp/chinadns@cache.db";
    if (!path) return;
    FILE *file = fopen(path, "wb");
    if (!file) { log_warning("failed to write cache db %s: %s", path, strerror(errno)); return; }
    size_t count = 0;
    for (struct list_node *n = cache_lru.next; n != &cache_lru; n = n->next) {
        struct cache_entry *e = container_of(n, struct cache_entry, lru);
        i32 remain = e->ttl - (i32)max((time_t)0, time(NULL) - e->update_time);
        if (!ttl_usable(remain)) continue;
        struct cache_db_header h = {
            .update_time = (i64)e->update_time, .hash = e->hash, .ttl = e->ttl,
            .refresh_ttl = e->refresh_ttl, .msg_len = e->msg_len, .qnamelen = e->qnamelen,
        };
        if (fwrite(&h, sizeof(h), 1, file) != 1 || fwrite(e->msg, e->msg_len, 1, file) != 1) break;
        ++count;
    }
    fclose(file);
    log_info("%zu entries to %s", count, path);
}

static struct verdict_entry *verdict_find(const void *query, int qnamelen, u32 hash) {
    const u8 *name = question_ptr(query);
    size_t len = (size_t)qnamelen - 1;
    for (struct verdict_entry *e = verdict_buckets[hash & (verdict_bucket_count - 1)]; e; e = e->hash_next)
        if (e->hash == hash && e->name_len == len && dns_name_equal(e->name, name, len)) return e;
    return NULL;
}

bool verdict_cache_get(const void *query, int qnamelen, bool *is_china) {
    if (!verdict_count || qnamelen <= 1) return false;
    u32 hash = dns_name_hash(question_ptr(query), (size_t)qnamelen - 1);
    struct verdict_entry *e = verdict_find(query, qnamelen, hash);
    if (!e) return false;
    *is_china = e->is_china;
    return true;
}

static void verdict_remove(struct verdict_entry *e) {
    size_t idx = e->hash & (verdict_bucket_count - 1);
    struct verdict_entry **p = &verdict_buckets[idx];
    while (*p && *p != e) p = &(*p)->hash_next;
    if (*p) *p = e->hash_next;
    list_remove(&e->fifo);
    free(e);
    --verdict_count;
}

void verdict_cache_add(const void *query, int qnamelen, bool is_china) {
    if (!g_config.verdict_cache_size || qnamelen <= 1) return;
    size_t len = (size_t)qnamelen - 1;
    u32 hash = dns_name_hash(question_ptr(query), len);
    struct verdict_entry *e = verdict_find(query, qnamelen, hash);
    if (e) { e->is_china = is_china; return; }
    while (verdict_count >= g_config.verdict_cache_size && !list_empty(&verdict_fifo))
        verdict_remove(container_of(verdict_fifo.next, struct verdict_entry, fifo));
    e = xmalloc(sizeof(*e) + len);
    e->hash = hash;
    e->name_len = (u16)len;
    e->is_china = is_china;
    memcpy(e->name, question_ptr(query), len);
    size_t idx = hash & (verdict_bucket_count - 1);
    e->hash_next = verdict_buckets[idx];
    verdict_buckets[idx] = e;
    list_insert_before(&verdict_fifo, &e->fifo);
    ++verdict_count;
}

static void verdict_load(void) {
    if (!g_config.verdict_cache_size || !g_config.verdict_cache_db) return;
    FILE *file = fopen(g_config.verdict_cache_db, "r");
    if (!file) {
        if (errno != ENOENT) log_warning("failed to open verdict db %s: %s", g_config.verdict_cache_db, strerror(errno));
        return;
    }
    char line[512];
    while (verdict_count < g_config.verdict_cache_size && fgets(line, sizeof(line), file)) {
        unsigned value;
        char ascii[DNS_NAME_MAXLEN + 1];
        if (sscanf(line, "%u %253s", &value, ascii) != 2) continue;
        u8 wire[DNS_NAME_WIRE_MAXLEN];
        size_t len = dns_ascii_to_wire(ascii, strlen(ascii), (char *)wire, NULL);
        if (len <= 1) continue;
        u8 fake[DNS_MSG_MINSIZE + DNS_NAME_WIRE_MAXLEN] = {0};
        memcpy(fake + dns_header_len(), wire, len);
        verdict_cache_add(fake, (int)len, value != 0);
    }
    fclose(file);
    log_info("%zu entries from %s", verdict_count, g_config.verdict_cache_db);
}

void verdict_cache_dump(bool manual) {
    if (!g_config.verdict_cache_size) return;
    const char *path = g_config.verdict_cache_db;
    if (!path && manual) path = "/tmp/chinadns@verdict-cache.db";
    if (!path) return;
    FILE *file = fopen(path, "w");
    if (!file) { log_warning("failed to write verdict db %s: %s", path, strerror(errno)); return; }
    size_t count = 0;
    for (struct list_node *n = verdict_fifo.next; n != &verdict_fifo; n = n->next) {
        struct verdict_entry *e = container_of(n, struct verdict_entry, fifo);
        char wire[DNS_NAME_WIRE_MAXLEN];
        char ascii[DNS_NAME_MAXLEN + 1];
        memcpy(wire, e->name, e->name_len);
        wire[e->name_len] = 0;
        if (!dns_wire_to_ascii(wire, e->name_len + 1, ascii)) continue;
        fprintf(file, "%u %s\n", e->is_china ? 1 : 0, ascii);
        ++count;
    }
    fclose(file);
    log_info("%zu entries to %s", count, path);
}

void cache_init(void) {
    list_init(&cache_lru);
    list_init(&verdict_fifo);
    if (g_config.cache_size) {
        cache_bucket_count = bucket_count_for(g_config.cache_size);
        cache_buckets = xcalloc(cache_bucket_count, sizeof(*cache_buckets));
    }
    if (g_config.verdict_cache_size) {
        verdict_bucket_count = bucket_count_for(g_config.verdict_cache_size);
        verdict_buckets = xcalloc(verdict_bucket_count, sizeof(*verdict_buckets));
    }
    for (size_t i = 0; i < g_config.cache_ignore.len; ++i)
        add_ignored_domain(g_config.cache_ignore.items[i]);
    cache_load();
    verdict_load();
}
