#pragma once

/* DNS response and tag:none verdict caches. */
#include "core.h"

void cache_init(void);
struct message *cache_get(const void *query, int qnamelen,
    i32 *ttl, i32 *refresh_ttl, bool *add_ip);
bool cache_add(void *reply, size_t len, int qnamelen, i32 *ttl);
void cache_dump(bool manual);

bool verdict_cache_get(const void *query, int qnamelen, bool *is_china);
void verdict_cache_add(const void *query, int qnamelen, bool is_china);
void verdict_cache_dump(bool manual);
