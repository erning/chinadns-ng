#define _GNU_SOURCE
#include "cache.h"
#include "config.h"
#include "dnl.h"
#include "local_rr.h"
#include "log.h"
#include "net.h"
#include "server.h"
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

static void init_domain_lists(void) {
    filenames_t files[TAG__MAX + 1] = {0};
    for (u8 tag = 0; tag <= TAG__MAX; ++tag) {
        struct strvec *vec = &g_config.groups[tag].dnl_files;
        if (!vec->len) continue;
        const char **items = xcalloc(vec->len + 1, sizeof(*items));
        for (size_t i = 0; i < vec->len; ++i) items[i] = vec->items[i];
        files[tag] = items;
    }
    dnl_init(files, g_config.gfwlist_first);
}

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    setvbuf(stdout, NULL, _IOLBF, 256);
    setenv("TZ", ":/etc/localtime", 0);

    config_parse(argc, argv);
    net_init();
    init_domain_lists();
    local_rr_init();
    cache_init();

    log_info("default domain tag: %s", tag_to_name(g_config.default_tag));
    log_info("upstream timeout: %u seconds", (uint)g_config.upstream_timeout);
    if (g_config.cache_size)
        log_info("DNS cache capacity: %u", (uint)g_config.cache_size);
    if (g_config.verdict_cache_size)
        log_info("verdict cache capacity: %u", (uint)g_config.verdict_cache_size);
    if (g_config.verbose)
        log_info("verbose runtime logging enabled");

    server_init();
    server_run();
    return 0;
}
