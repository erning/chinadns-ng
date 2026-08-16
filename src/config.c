#define _GNU_SOURCE
#include "config.h"
#include "dns.h"
#include "ipset.h"
#include "log.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct config g_config = {
    .gfwlist_first = true,
    .default_tag = TAG_NONE,
    .trustdns_packet_n = 1,
    .upstream_timeout = 5,
    .cache_nodata_ttl = 60,
};

enum value_kind { VALUE_NONE, VALUE_REQUIRED, VALUE_OPTIONAL };
typedef void (*option_fn)(const char *value);

struct option_def {
    char short_name;
    const char *long_name;
    enum value_kind value;
    option_fn apply;
};

static u8 current_group = TAG_NONE;
static unsigned config_depth;

static void fail(const char *what, const char *value) {
    if (value)
        fprintf(stderr, "chinadns-ng: %s: '%s'\n", what, value);
    else
        fprintf(stderr, "chinadns-ng: %s\n", what);
    fprintf(stderr, "Try 'chinadns-ng --help' for more information.\n");
    exit(2);
}

static unsigned long parse_uint(const char *value, unsigned long max_value, bool allow_zero) {
    char *end = NULL;
    errno = 0;
    unsigned long n = strtoul(value, &end, 10);
    if (errno || !*value || *end || n > max_value || (!allow_zero && n == 0))
        fail("invalid integer", value);
    return n;
}

static void split_push(struct strvec *vec, const char *value) {
    const char *p = value;
    do {
        const char *end = strchr(p, ',');
        size_t len = end ? (size_t)(end - p) : strlen(p);
        if (!len) fail("empty list item", value);
        strvec_push_n(vec, p, len);
        p = end ? end + 1 : NULL;
    } while (p);
}

static void upstream_push(struct upstream_vec *vec, const struct upstream_config *upstream) {
    for (size_t i = 0; i < vec->len; ++i) {
        struct upstream_config *old = &vec->items[i];
        if (old->proto == upstream->proto && old->addr.len == upstream->addr.len &&
            memcmp(&old->addr.storage, &upstream->addr.storage, upstream->addr.len) == 0 &&
            strcmp(old->host ? old->host : "", upstream->host ? upstream->host : "") == 0) {
            old->count = upstream->count;
            old->life = upstream->life;
            old->fallback = upstream->fallback;
            /* the URL must reflect the latest spec, e.g. when the same upstream
             * is repeated with ?fallback, so startup logs show the real config */
            free(old->url);
            old->url = upstream->url; /* ownership moved; the caller's copy is a stack temp */
            free(upstream->host);
            return;
        }
    }
    if (vec->len == vec->cap) {
        vec->cap = vec->cap ? vec->cap * 2 : 4;
        vec->items = xrealloc(vec->items, vec->cap * sizeof(*vec->items));
    }
    vec->items[vec->len++] = *upstream;
}

static void add_one_upstream(u8 tag, enum upstream_proto proto, const char *host,
    const char *ip, u16 port, u16 count, u16 life, bool fallback, const char *source) {
    struct upstream_config u = {
        .proto = proto,
        .host = *host ? xstrdup(host) : NULL,
        .url = xstrdup(source),
        .count = count,
        .life = life,
        .tag = tag,
        .fallback = fallback,
    };
    if (!socket_addr_parse(&u.addr, ip, port))
        fail("invalid upstream IP", ip);
    upstream_push(&g_config.groups[tag].upstreams, &u);
}

static void parse_upstream(u8 tag, const char *source) {
    char *work = xstrdup(source);
    char *rest = work;
    enum upstream_proto proto = UP_RAW_UDP;
    u16 std_port = 53;
    char *scheme = strstr(rest, "://");
    if (scheme) {
        *scheme = '\0';
        if (strcmp(rest, "udp") == 0) proto = UP_UDP;
        else if (strcmp(rest, "tcp") == 0) proto = UP_TCP;
        else if (strcmp(rest, "tls") == 0) {
            proto = UP_TLS;
            std_port = 853;
        } else fail("invalid upstream protocol", rest);
        rest = scheme + 3;
    }

    char *host = "";
    char *at = strchr(rest, '@');
    if (at) {
        *at = '\0';
        host = rest;
        rest = at + 1;
        if (!*host || proto != UP_TLS)
            fail("upstream host is only valid for TLS", source);
    }

    u16 count = 10;
    u16 life = 10;
    bool fallback = false;
    char *query;
    while ((query = strrchr(rest, '?')) != NULL) {
        *query++ = '\0';
        if (strcmp(query, "fallback") == 0) { /* valueless flag */
            fallback = true;
            continue;
        }
        char *eq = strchr(query, '=');
        if (!eq) fail("invalid upstream parameter", query);
        *eq++ = '\0';
        u16 value = (u16)parse_uint(eq, UINT16_MAX, true);
        if (strcmp(query, "count") == 0) count = value;
        else if (strcmp(query, "life") == 0) life = value;
        else fail("unknown upstream parameter", query);
    }

    u16 port = std_port;
    char *hash = strrchr(rest, '#');
    if (hash) {
        *hash++ = '\0';
        port = (u16)parse_uint(hash, UINT16_MAX, false);
    }
    if (!*rest) fail("missing upstream IP", source);

    if (!scheme) {
        add_one_upstream(tag, UP_RAW_UDP, "", rest, port, count, life, fallback, source);
        add_one_upstream(tag, UP_RAW_TCP, "", rest, port, count, life, fallback, source);
    } else {
        add_one_upstream(tag, proto, host, rest, port, count, life, fallback, source);
    }
    free(work);
}

static void add_upstreams(u8 tag, const char *value) {
    const char *p = value;
    do {
        const char *end = strchr(p, ',');
        size_t len = end ? (size_t)(end - p) : strlen(p);
        if (!len) fail("empty upstream", value);
        char *one = xstrndup(p, len);
        parse_upstream(tag, one);
        free(one);
        p = end ? end + 1 : NULL;
    } while (p);
}

static void bind_port_push(u16 port, bool tcp, bool udp) {
    struct bind_port_vec *vec = &g_config.bind_ports;
    for (size_t i = 0; i < vec->len; ++i) {
        if (vec->items[i].port == port) {
            vec->items[i].tcp = tcp;
            vec->items[i].udp = udp;
            return;
        }
    }
    if (vec->len == vec->cap) {
        vec->cap = vec->cap ? vec->cap * 2 : 4;
        vec->items = xrealloc(vec->items, vec->cap * sizeof(*vec->items));
    }
    vec->items[vec->len++] = (struct bind_port){ .port = port, .tcp = tcp, .udp = udp };
}

static void opt_bind_addr(const char *value) {
    struct socket_addr addr;
    if (!socket_addr_parse(&addr, value, 1)) fail("invalid bind IP", value);
    strvec_push(&g_config.bind_ips, value);
}

static void opt_bind_port(const char *value) {
    char *work = xstrdup(value);
    char *proto = strchr(work, '@');
    if (proto) *proto++ = '\0';
    u16 port = (u16)parse_uint(work, UINT16_MAX, false);
    bool tcp = true, udp = true;
    if (proto) {
        if (strcmp(proto, "tcp") == 0) udp = false;
        else if (strcmp(proto, "udp") == 0) tcp = false;
        else if (strcmp(proto, "tcp+udp") && strcmp(proto, "udp+tcp"))
            fail("invalid bind protocol", proto);
    }
    bind_port_push(port, tcp, udp);
    free(work);
}

static void opt_china_dns(const char *value) { add_upstreams(TAG_CHN, value); }
static void opt_trust_dns(const char *value) { add_upstreams(TAG_GFW, value); }
static void opt_chnlist(const char *value) { split_push(&g_config.groups[TAG_CHN].dnl_files, value); }
static void opt_gfwlist(const char *value) { split_push(&g_config.groups[TAG_GFW].dnl_files, value); }
static void opt_chn_first(const char *value) { (void)value; g_config.gfwlist_first = false; }

static void opt_default_tag(const char *value) {
    u8 tag = tag_from_name(value);
    if (!tag_is_valid(tag) && tag != TAG_NONE) fail("invalid default tag", value);
    g_config.default_tag = tag;
}

static void set_group_ipset(u8 tag, const char *value) {
    free(g_config.groups[tag].ipset_name46);
    g_config.groups[tag].ipset_name46 = xstrdup(value ? value : "");
}

static void opt_add_chn_ip(const char *value) { set_group_ipset(TAG_CHN, value); }
static void opt_add_gfw_ip(const char *value) { set_group_ipset(TAG_GFW, value); }
static void opt_ipset4(const char *value) { free(g_config.chnroute_name); g_config.chnroute_name = xstrdup(value); }
static void opt_ipset6(const char *value) { free(g_config.chnroute6_name); g_config.chnroute6_name = xstrdup(value); }

static void opt_group(const char *value) {
    bool overflow = false;
    u8 tag = tag_register(value, &overflow);
    if (!tag_is_valid(tag))
        fail(overflow ? "too many groups" : "invalid group name", value);
    current_group = tag;
}

static void require_group(const char *value) {
    if (current_group == TAG_NONE) fail("option used outside group", value);
}

static void opt_group_dnl(const char *value) { require_group(value); split_push(&g_config.groups[current_group].dnl_files, value); }
static void require_forward_group(const char *value) {
    require_group(value);
    if (tag_is_null(current_group)) fail("option is invalid for null group", value);
}
static void opt_group_upstream(const char *value) { require_forward_group(value); add_upstreams(current_group, value); }
static void opt_group_ipset(const char *value) { require_forward_group(value); set_group_ipset(current_group, value); }

static void add_ip6_rule(struct ip6_filter *filter, const char *rule) {
    if (!rule) {
        filter->china_ip = true;
        filter->non_china_ip = true;
    } else if (strcmp(rule, "ip:china") == 0) {
        filter->china_ip = true;
    } else if (strcmp(rule, "ip:non_china") == 0) {
        filter->non_china_ip = true;
    } else {
        fail("invalid no-ipv6 rule", rule);
    }
}

static void opt_no_ipv6(const char *value) {
    if (!value) {
        for (u8 tag = 0; tag <= TAG_NONE; ++tag) add_ip6_rule(&g_config.groups[tag].ip6, NULL);
        return;
    }
    char *work = xstrdup(value);
    char *save = NULL;
    for (char *rule = strtok_r(work, ",", &save); rule; rule = strtok_r(NULL, ",", &save)) {
        if (strncmp(rule, "tag:", 4) == 0) {
            char *ip_rule = strchr(rule, '@');
            if (ip_rule) *ip_rule++ = '\0';
            u8 tag = tag_from_name(rule + 4);
            if (!tag_is_valid(tag) && tag != TAG_NONE) fail("invalid no-ipv6 tag", rule + 4);
            add_ip6_rule(&g_config.groups[tag].ip6, ip_rule);
        } else {
            for (u8 tag = 0; tag <= TAG_NONE; ++tag) add_ip6_rule(&g_config.groups[tag].ip6, rule);
        }
    }
    free(work);
}

static void opt_filter_qtype(const char *value) {
    if (!g_config.filter_qtypes)
        g_config.filter_qtypes = xcalloc(bitvec_n((size_t)UINT16_MAX + 1), sizeof(*g_config.filter_qtypes));
    char *work = xstrdup(value);
    char *save = NULL;
    for (char *p = strtok_r(work, ",", &save); p; p = strtok_r(NULL, ",", &save)) {
        u16 qtype = (u16)parse_uint(p, UINT16_MAX, true);
        bitvec_set1(g_config.filter_qtypes, qtype);
    }
    free(work);
}

static void opt_cache(const char *value) { g_config.cache_size = (u16)parse_uint(value, UINT16_MAX, true); }
static void opt_cache_stale(const char *value) { g_config.cache_stale = (u32)parse_uint(value, UINT32_MAX, true); }
static void opt_cache_refresh(const char *value) { g_config.cache_refresh = (u8)parse_uint(value, UINT8_MAX, true); }
static void opt_cache_nodata(const char *value) { g_config.cache_nodata_ttl = (i32)parse_uint(value, INT32_MAX, true); }
static void opt_cache_min(const char *value) { g_config.cache_min_ttl = (i32)parse_uint(value, INT32_MAX, true); }
static void opt_cache_max(const char *value) { g_config.cache_max_ttl = (i32)parse_uint(value, INT32_MAX, true); }
static void opt_cache_ignore(const char *value) { strvec_push(&g_config.cache_ignore, value); }
static void opt_cache_db(const char *value) { free(g_config.cache_db); g_config.cache_db = xstrdup(value); }
static void opt_verdict_cache(const char *value) { g_config.verdict_cache_size = (u16)parse_uint(value, UINT16_MAX, true); }
static void opt_verdict_db(const char *value) { free(g_config.verdict_cache_db); g_config.verdict_cache_db = xstrdup(value); }
static void opt_hosts(const char *value) { strvec_push(&g_config.hosts_files, value ? value : "/etc/hosts"); }
static void opt_local_rr(const char *value) { strvec_push(&g_config.local_rr, value); }
static void opt_cert_verify(const char *value) { (void)value; g_config.cert_verify = true; }
static void opt_ca_certs(const char *value) { free(g_config.ca_certs); g_config.ca_certs = xstrdup(value); }
static void opt_no_blacklist(const char *value) { (void)value; ipset_blacklist = false; }
static void opt_timeout(const char *value) { g_config.upstream_timeout = (u8)parse_uint(value, UINT8_MAX, false); }
static void opt_repeat(const char *value) { unsigned long n = parse_uint(value, UINT8_MAX, false); g_config.trustdns_packet_n = (u8)min(n, 5); }
static void opt_noip(const char *value) { (void)value; g_config.noip_as_chnip = true; }
static void opt_fair(const char *value) { (void)value; }
static void opt_reuse(const char *value) { (void)value; g_config.reuse_port = true; }
static void opt_verbose_(const char *value) { (void)value; g_config.verbose = true; log_verbose_enabled = true; }
static void opt_version(const char *value) { (void)value; printf("ChinaDNS-NG %s | pure-c-linux | <%s>\n", CHINADNS_VERSION, CHINADNS_URL); exit(0); }
static void opt_help(const char *value) { (void)value; config_show_help(stdout); exit(0); }

static void parse_config_file(const char *value);

static const struct option_def options[] = {
    {'C', "config", VALUE_REQUIRED, parse_config_file},
    {'b', "bind-addr", VALUE_REQUIRED, opt_bind_addr},
    {'l', "bind-port", VALUE_REQUIRED, opt_bind_port},
    {'c', "china-dns", VALUE_REQUIRED, opt_china_dns},
    {'t', "trust-dns", VALUE_REQUIRED, opt_trust_dns},
    {'m', "chnlist-file", VALUE_REQUIRED, opt_chnlist},
    {'g', "gfwlist-file", VALUE_REQUIRED, opt_gfwlist},
    {'M', "chnlist-first", VALUE_NONE, opt_chn_first},
    {'d', "default-tag", VALUE_REQUIRED, opt_default_tag},
    {'a', "add-tagchn-ip", VALUE_OPTIONAL, opt_add_chn_ip},
    {'A', "add-taggfw-ip", VALUE_REQUIRED, opt_add_gfw_ip},
    {'4', "ipset-name4", VALUE_REQUIRED, opt_ipset4},
    {'6', "ipset-name6", VALUE_REQUIRED, opt_ipset6},
    {0, "group", VALUE_REQUIRED, opt_group},
    {0, "group-dnl", VALUE_REQUIRED, opt_group_dnl},
    {0, "group-upstream", VALUE_REQUIRED, opt_group_upstream},
    {0, "group-ipset", VALUE_REQUIRED, opt_group_ipset},
    {'N', "no-ipv6", VALUE_OPTIONAL, opt_no_ipv6},
    {0, "filter-qtype", VALUE_REQUIRED, opt_filter_qtype},
    {0, "cache", VALUE_REQUIRED, opt_cache},
    {0, "cache-stale", VALUE_REQUIRED, opt_cache_stale},
    {0, "cache-refresh", VALUE_REQUIRED, opt_cache_refresh},
    {0, "cache-nodata-ttl", VALUE_REQUIRED, opt_cache_nodata},
    {0, "cache-min-ttl", VALUE_REQUIRED, opt_cache_min},
    {0, "cache-max-ttl", VALUE_REQUIRED, opt_cache_max},
    {0, "cache-ignore", VALUE_REQUIRED, opt_cache_ignore},
    {0, "cache-db", VALUE_REQUIRED, opt_cache_db},
    {0, "verdict-cache", VALUE_REQUIRED, opt_verdict_cache},
    {0, "verdict-cache-db", VALUE_REQUIRED, opt_verdict_db},
    {0, "hosts", VALUE_OPTIONAL, opt_hosts},
    {0, "dns-rr-ip", VALUE_REQUIRED, opt_local_rr},
    {0, "cert-verify", VALUE_NONE, opt_cert_verify},
    {0, "ca-certs", VALUE_REQUIRED, opt_ca_certs},
    {0, "no-ipset-blacklist", VALUE_NONE, opt_no_blacklist},
    {'o', "timeout-sec", VALUE_REQUIRED, opt_timeout},
    {'p', "repeat-times", VALUE_REQUIRED, opt_repeat},
    {'n', "noip-as-chnip", VALUE_NONE, opt_noip},
    {'f', "fair-mode", VALUE_NONE, opt_fair},
    {'r', "reuse-port", VALUE_NONE, opt_reuse},
    {'v', "verbose", VALUE_NONE, opt_verbose_},
    {'V', "version", VALUE_NONE, opt_version},
    {'h', "help", VALUE_NONE, opt_help},
};

static const struct option_def *find_option(const char *name, size_t len) {
    for (size_t i = 0; i < array_n(options); ++i) {
        if ((len == 1 && options[i].short_name == name[0]) ||
            (strlen(options[i].long_name) == len && memcmp(options[i].long_name, name, len) == 0))
            return &options[i];
    }
    return NULL;
}

static void apply_option(const struct option_def *def, const char *value) {
    if (def->value == VALUE_REQUIRED && !value) fail("missing option value", def->long_name);
    if (def->value == VALUE_NONE && value) fail("unexpected option value", def->long_name);
    if (value && !*value) fail("empty option value", def->long_name);
    def->apply(value);
}

static void parse_config_file(const char *path) {
    if (++config_depth > 10) fail("config chain is too deep", path);
    FILE *file = fopen(path, "r");
    if (!file) fail("cannot open config", path);
    char *line = NULL;
    size_t cap = 0;
    unsigned line_no = 0;
    while (getline(&line, &cap, file) >= 0) {
        ++line_no;
        char *save = NULL;
        char *name = strtok_r(line, " \t\r\n", &save);
        if (!name || *name == '#') continue;
        char *value = strtok_r(NULL, " \t\r\n", &save);
        if (strtok_r(NULL, " \t\r\n", &save)) {
            fprintf(stderr, "%s:%u: too many values\n", path, line_no);
            exit(2);
        }
        while (*name == '-') ++name;
        const struct option_def *def = find_option(name, strlen(name));
        if (!def) {
            fprintf(stderr, "%s:%u: unknown option '%s'\n", path, line_no, name);
            exit(2);
        }
        apply_option(def, value);
    }
    free(line);
    fclose(file);
    --config_depth;
}

static bool group_has_fallback(const struct upstream_vec *vec) {
    for (size_t i = 0; i < vec->len; ++i)
        if (vec->items[i].fallback) return true;
    return false;
}

static bool group_has_primary(const struct upstream_vec *vec) {
    for (size_t i = 0; i < vec->len; ++i)
        if (!vec->items[i].fallback) return true;
    return false;
}

static void finalize(void) {
    if (!g_config.bind_ips.len) strvec_push(&g_config.bind_ips, "127.0.0.1");
    if (!g_config.bind_ports.len) bind_port_push(65353, true, true);
    if (!g_config.groups[TAG_CHN].upstreams.len) add_upstreams(TAG_CHN, "114.114.114.114");
    if (!g_config.groups[TAG_GFW].upstreams.len) add_upstreams(TAG_GFW, "8.8.8.8");
    if (!g_config.chnroute_name) g_config.chnroute_name = xstrdup("chnroute");
    if (!g_config.chnroute6_name) g_config.chnroute6_name = xstrdup("chnroute6");

    char *set = g_config.groups[TAG_CHN].ipset_name46;
    if (set && !*set) {
        size_t len = strlen(g_config.chnroute_name) + strlen(g_config.chnroute6_name) + 2;
        set = xmalloc(len);
        snprintf(set, len, "%s,%s", g_config.chnroute_name, g_config.chnroute6_name);
        free(g_config.groups[TAG_CHN].ipset_name46);
        g_config.groups[TAG_CHN].ipset_name46 = set;
    }

    for (u8 tag = TAG__USER; tag <= TAG__MAX; ++tag) {
        if (!tag_is_valid(tag)) continue;
        if (tag != g_config.default_tag && !g_config.groups[tag].dnl_files.len)
            fail("user group has no domain list", tag_to_name(tag));
        if (!tag_is_null(tag) && !g_config.groups[tag].upstreams.len)
            fail("user group has no upstream", tag_to_name(tag));
    }

    for (u8 tag = 0; tag <= TAG__MAX; ++tag) {
        struct group_config *group = &g_config.groups[tag];
        /* like the Zig version, every group starts healthy (also groups without
         * ?fallback upstreams, for which the health flag is simply unused) */
        group->primary_healthy = true;
        if (!group->upstreams.len || !group_has_fallback(&group->upstreams)) continue;
        if (!group_has_primary(&group->upstreams))
            fail("fallback upstream without primary upstream", tag_to_name(tag));
        group->fallback_enabled = true;
    }
}

void config_parse(int argc, char **argv) {
    for (int i = 1; i < argc; ++i) {
        const char *arg = argv[i];
        if (arg[0] != '-') fail("unexpected positional argument", arg);
        const char *name;
        size_t name_len;
        const char *value = NULL;
        const char *eq;
        if (arg[1] == '-') {
            name = arg + 2;
            if (!*name) fail("invalid option", arg);
            eq = strchr(name, '=');
            name_len = eq ? (size_t)(eq - name) : strlen(name);
            if (eq) value = eq + 1;
        } else {
            name = arg + 1;
            name_len = 1;
            if (!*name) fail("invalid option", arg);
            if (arg[2] == '=') value = arg + 3;
            else if (arg[2]) value = arg + 2;
        }
        const struct option_def *def = find_option(name, name_len);
        if (!def) fail("unknown option", arg);
        if (!value && def->value != VALUE_NONE && i + 1 < argc &&
            (def->value == VALUE_REQUIRED || argv[i + 1][0] != '-'))
            value = argv[++i];
        apply_option(def, value);
    }
    finalize();
}

bool config_qtype_filtered(u16 qtype) {
    return g_config.filter_qtypes && bitvec_get(g_config.filter_qtypes, qtype);
}

bool config_ip6_filter_query(u8 tag) {
    const struct ip6_filter *filter = &g_config.groups[tag].ip6;
    return filter->china_ip && filter->non_china_ip;
}

bool config_ip6_filter_reply(u8 tag, int result) {
    const struct ip6_filter *filter = &g_config.groups[tag].ip6;
    return (result == DNS_TEST_IP_IS_CHINA_IP && filter->china_ip) ||
        (result == DNS_TEST_IP_NON_CHINA_IP && filter->non_china_ip);
}

void config_show_help(FILE *out) {
    fputs(
        "usage: chinadns-ng <options...>. the existing options are as follows:\n"
        " -C, --config <path>                  format similar to the long option\n"
        " -b, --bind-addr <ip>                 listen address, default: 127.0.0.1\n"
        " -l, --bind-port <port[@proto]>       listen port number, default: 65353\n"
        " -c, --china-dns <upstreams>          china dns server, default: <114 DNS>\n"
        " -t, --trust-dns <upstreams>          trust dns server, default: <Google DNS>\n"
        " -m, --chnlist-file <paths>           path(s) of chnlist, '-' indicate stdin\n"
        " -g, --gfwlist-file <paths>           path(s) of gfwlist, '-' indicate stdin\n"
        " -M, --chnlist-first                  match chnlist first, default gfwlist first\n"
        " -d, --default-tag <tag>              chn or gfw or <user-tag> or none(default)\n"
        " -a, --add-tagchn-ip [set4,set6]      add the ip of name-tag:chn to ipset/nftset\n"
        "                                      use '--ipset-name4/6' setname if no value\n"
        " -A, --add-taggfw-ip <set4,set6>      add the ip of name-tag:gfw to ipset/nftset\n"
        " -4, --ipset-name4 <set4>             ip test for tag:none, default: chnroute\n"
        " -6, --ipset-name6 <set6>             ip test for tag:none, default: chnroute6\n"
        "                                      if setname contains @, then use nftset\n"
        "                                      format: family_name@table_name@set_name\n"
        "     --group <name>                   define rule group: {dnl, upstream, ipset}\n"
        "     --group-dnl <paths>              domain name list for the current group\n"
        "     --group-upstream <upstreams>     upstream dns server for the current group\n"
        "     --group-ipset <set4,set6>        add the ip of the current group to ipset\n"
        " -N, --no-ipv6 [rules]                tag:<name>[@ip:*], ip:china, ip:non_china\n"
        "                                      if no rules, then filter all AAAA queries\n"
        "     --filter-qtype <qtypes>          filter queries with the given qtype (u16)\n"
        "     --cache <size>                   enable dns caching, size 0 means disabled\n"
        "     --cache-stale <N>               use stale cache: expired time <= N(second)\n"
        "     --cache-refresh <N>             pre-refresh the cached data if TTL <= N(%)\n"
        "     --cache-nodata-ttl <ttl>        TTL of the NODATA response, default is 60\n"
        "     --cache-min-ttl <ttl>           if record.ttl < min_ttl, use min_ttl\n"
        "     --cache-max-ttl <ttl>           if record.ttl > max_ttl, use max_ttl\n"
        "     --cache-ignore <domain>         ignore cache for this domain suffix\n"
        "     --cache-db <path>               dns cache persistence (from/to db file)\n"
        "     --verdict-cache <size>          cache verdicts for tag:none domains\n"
        "     --verdict-cache-db <path>       verdict cache persistence db file\n"
        "     --hosts [path]                  load hosts file, default: /etc/hosts\n"
        "     --dns-rr-ip <names>=<ips>       define local A/AAAA resource records\n"
        "     --cert-verify                   enable SSL certificate validation\n"
        "     --ca-certs <path>               CA certificates for SSL validation\n"
        "     --no-ipset-blacklist            disable the built-in add-ip blacklist\n"
        "                                      blacklist: 127.0.0.0/8, 0.0.0.0/8, ::1, ::\n"
        " -o, --timeout-sec <sec>              upstream response timeout, default: 5\n"
        " -p, --repeat-times <num>             trustdns packets, default: 1, max: 5\n"
        " -n, --noip-as-chnip                  allow no-IP response from chinadns\n"
        " -f, --fair-mode                      compatibility no-op; fair mode is always on\n"
        " -r, --reuse-port                     enable SO_REUSEPORT, default: disabled\n"
        " -v, --verbose                        print verbose logs, default: disabled\n"
        " -V, --version                        print version and exit\n"
        " -h, --help                           print this help and exit\n"
        "bug report: " CHINADNS_URL "\n",
        out);
}
