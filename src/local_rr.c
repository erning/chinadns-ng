#define _GNU_SOURCE
#include "local_rr.h"
#include "config.h"
#include "core.h"
#include "dns.h"
#include "log.h"
#include "net.h"
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct rr_entry {
    struct rr_entry *next;
    u32 hash;
    u16 name_len;
    u16 count4;
    u16 count6;
    size_t len4;
    size_t len6;
    u8 *rr4;
    u8 *rr6;
    u8 name[];
};

#define RR_INITIAL_BUCKETS 256

static struct rr_entry **buckets;
static size_t bucket_count;
static size_t entry_count;

struct struct_alignto(1) rr_head {
    u16 name;
    u16 type;
    u16 class_;
    u32 ttl;
    u16 data_len;
};

STATIC_ASSERT(sizeof(struct rr_head) == 12);

static struct rr_entry *find_entry(const void *name, size_t len, u32 hash) {
    for (struct rr_entry *e = buckets[hash & (bucket_count - 1)]; e; e = e->next)
        if (e->hash == hash && e->name_len == len && memcmp(e->name, name, len) == 0)
            return e;
    return NULL;
}

static struct rr_entry *get_entry(const void *name, size_t len) {
    u32 hash = calc_hashv(name, len);
    struct rr_entry *e = find_entry(name, len, hash);
    if (e) return e;
    if (entry_count >= bucket_count * 2) {
        size_t new_count = bucket_count * 2;
        struct rr_entry **new_buckets = xcalloc(new_count, sizeof(*new_buckets));
        for (size_t i = 0; i < bucket_count; ++i) {
            struct rr_entry *item = buckets[i];
            while (item) {
                struct rr_entry *next = item->next;
                size_t idx = item->hash & (new_count - 1);
                item->next = new_buckets[idx];
                new_buckets[idx] = item;
                item = next;
            }
        }
        free(buckets);
        buckets = new_buckets;
        bucket_count = new_count;
    }
    e = xcalloc(1, sizeof(*e) + len);
    e->hash = hash;
    e->name_len = (u16)len;
    memcpy(e->name, name, len);
    size_t idx = hash & (bucket_count - 1);
    e->next = buckets[idx];
    buckets[idx] = e;
    ++entry_count;
    return e;
}

static bool record_exists(const u8 *records, size_t len, const void *ip, size_t ip_len) {
    size_t rr_len = sizeof(struct rr_head) + ip_len;
    for (size_t off = 0; off + rr_len <= len; off += rr_len)
        if (memcmp(records + off + sizeof(struct rr_head), ip, ip_len) == 0)
            return true;
    return false;
}

static bool add_ip(const char *ascii_name, const char *ip) {
    u8 wire[DNS_NAME_WIRE_MAXLEN];
    size_t wire_len = dns_ascii_to_wire(ascii_name, strlen(ascii_name), (char *)wire, NULL);
    if (wire_len <= 1) {
        log_error("invalid local domain: %s", ascii_name);
        return false;
    }

    u8 net_ip[IPV6_LEN];
    int family = strchr(ip, ':') ? AF_INET6 : AF_INET;
    size_t ip_len = family == AF_INET ? IPV4_LEN : IPV6_LEN;
    if (inet_pton(family, ip, net_ip) != 1) {
        log_error("invalid local IP: %s", ip);
        return false;
    }

    struct rr_entry *e = get_entry(wire, wire_len - 1);
    u8 **records = family == AF_INET ? &e->rr4 : &e->rr6;
    size_t *records_len = family == AF_INET ? &e->len4 : &e->len6;
    u16 *count = family == AF_INET ? &e->count4 : &e->count6;
    if (record_exists(*records, *records_len, net_ip, ip_len)) return true;

    size_t rr_len = sizeof(struct rr_head) + ip_len;
    size_t reply_len = dns_header_len() + dns_question_len((int)wire_len) + *records_len + rr_len;
    if (reply_len > DNS_MSG_MAXSIZE) {
        log_error("too many local %s records for %s", family == AF_INET ? "A" : "AAAA", ascii_name);
        return false;
    }
    *records = xrealloc(*records, *records_len + rr_len);
    struct rr_head *rr = (struct rr_head *)(*records + *records_len);
    rr->name = htons(0xc000u + dns_header_len());
    rr->type = htons(family == AF_INET ? DNS_TYPE_A : DNS_TYPE_AAAA);
    rr->class_ = htons(DNS_CLASS_IN);
    rr->ttl = 0;
    rr->data_len = htons((u16)ip_len);
    memcpy((u8 *)rr + sizeof(*rr), net_ip, ip_len);
    *records_len += rr_len;
    ++*count;
    return true;
}

static bool parse_definition(const char *value) {
    char *work = xstrdup(value);
    char *eq = strchr(work, '=');
    if (!eq || eq == work || !eq[1]) {
        log_error("invalid --dns-rr-ip value: %s", value);
        free(work);
        return false;
    }
    *eq++ = '\0';
    char *name_save = NULL;
    for (char *name = strtok_r(work, ",", &name_save); name; name = strtok_r(NULL, ",", &name_save)) {
        char *ips = xstrdup(eq);
        char *ip_save = NULL;
        for (char *ip = strtok_r(ips, ",", &ip_save); ip; ip = strtok_r(NULL, ",", &ip_save)) {
            if (!add_ip(name, ip)) {
                free(ips);
                free(work);
                return false;
            }
        }
        free(ips);
    }
    free(work);
    return true;
}

static bool read_hosts(const char *path) {
    FILE *file = fopen(path, "r");
    if (!file) {
        log_error("failed to open hosts file %s: (%d) %s", path, errno, strerror(errno));
        return false;
    }
    char *line = NULL;
    size_t cap = 0;
    while (getline(&line, &cap, file) >= 0) {
        char *comment = strchr(line, '#');
        if (comment) *comment = '\0';
        char *save = NULL;
        char *ip = strtok_r(line, " \t\r\n", &save);
        if (!ip) continue;
        char *name = strtok_r(NULL, " \t\r\n", &save);
        if (!name) {
            log_error("missing domain in hosts file %s", path);
            free(line);
            fclose(file);
            return false;
        }
        do {
            if (!add_ip(name, ip)) {
                free(line);
                fclose(file);
                return false;
            }
        } while ((name = strtok_r(NULL, " \t\r\n", &save)) != NULL);
    }
    free(line);
    fclose(file);
    return true;
}

void local_rr_init(void) {
    bucket_count = RR_INITIAL_BUCKETS;
    buckets = xcalloc(bucket_count, sizeof(*buckets));
    for (size_t i = 0; i < g_config.hosts_files.len; ++i)
        if (!read_hosts(g_config.hosts_files.items[i])) exit(2);
    for (size_t i = 0; i < g_config.local_rr.len; ++i)
        if (!parse_definition(g_config.local_rr.items[i])) exit(2);
}

bool local_rr_find(const void *msg, int qnamelen,
    const void **answer, size_t *answer_len, u16 *answer_count) {
    if (qnamelen <= 1) return false;
    const u8 *qname = (const u8 *)msg + dns_header_len();
    size_t name_len = (size_t)qnamelen - 1;
    struct rr_entry *e = find_entry(qname, name_len, calc_hashv(qname, name_len));
    if (!e) return false;
    switch (dns_get_qtype(msg, qnamelen)) {
        case DNS_TYPE_A:
            if (!e->count4) return false;
            *answer = e->rr4;
            *answer_len = e->len4;
            *answer_count = e->count4;
            return true;
        case DNS_TYPE_AAAA:
            if (!e->count6) return false;
            *answer = e->rr6;
            *answer_len = e->len6;
            *answer_count = e->count6;
            return true;
        default:
            return false;
    }
}
