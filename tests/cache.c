#include "../src/cache.c"
#include <assert.h>

int main(void) {
    g_config.verdict_cache_size = 8;
    cache_init();
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
    puts("cache: case-insensitive verdicts: PASS");
    return 0;
}
