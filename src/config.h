#pragma once

#include "core.h"
#include <stdio.h>

enum upstream_proto {
    UP_RAW_UDP,
    UP_RAW_TCP,
    UP_UDP,
    UP_TCP,
    UP_TLS,
};

struct upstream_config {
    enum upstream_proto proto;
    struct socket_addr addr;
    char *host;
    char *url;
    u16 count;
    u16 life;
    u8 tag;
    bool fallback; /* queried (alongside primaries) only while the group is unhealthy */
    void *runtime;
};

struct upstream_vec {
    struct upstream_config *items;
    size_t len;
    size_t cap;
};

struct ip6_filter {
    bool china_ip;
    bool non_china_ip;
};

struct group_config {
    struct strvec dnl_files;
    struct upstream_vec upstreams;
    char *ipset_name46;
    struct ip6_filter ip6;

    /* passive health-check of the primary (non-fallback) upstreams, enabled when
     * the group has `?fallback` upstream(s). `primary_healthy == true` is the
     * steady state: only primaries are queried; `false` means primaries went
     * silent, so fallbacks are queried too. driven by real query results only:
     * a good primary reply sets it true (`group_primary_alive`), `pending_since`
     * ageing out flips it false (`group_health_check`). */
    bool fallback_enabled;
    bool primary_healthy;
    u64 pending_since; /* monotime(ms) of the oldest unanswered primary query, 0 = none */
};

struct bind_port {
    u16 port;
    bool tcp;
    bool udp;
};

struct bind_port_vec {
    struct bind_port *items;
    size_t len;
    size_t cap;
};

struct config {
    bool verbose;
    bool reuse_port;
    bool noip_as_chnip;
    bool gfwlist_first;
    bool cert_verify;

    u8 default_tag;
    u8 trustdns_packet_n;
    u8 upstream_timeout;

    struct strvec bind_ips;
    struct bind_port_vec bind_ports;
    struct group_config groups[TAG_NONE + 1];

    char *chnroute_name;
    char *chnroute6_name;
    char *ca_certs;

    bitvec_t *filter_qtypes;

    u16 cache_size;
    u32 cache_stale;
    u8 cache_refresh;
    i32 cache_nodata_ttl;
    i32 cache_min_ttl;
    i32 cache_max_ttl;
    struct strvec cache_ignore;
    char *cache_db;

    u16 verdict_cache_size;
    char *verdict_cache_db;

    struct strvec hosts_files;
    struct strvec local_rr;
};

extern struct config g_config;

void config_parse(int argc, char **argv);
void config_show_help(FILE *out);

bool config_qtype_filtered(u16 qtype);
bool config_ip6_filter_query(u8 tag);
bool config_ip6_filter_reply(u8 tag, int ip_test_result);
