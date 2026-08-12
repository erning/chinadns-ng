#define _GNU_SOURCE
#include "misc.h"
#include "uthash.h"
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

bool is_dir(const char *path) {
    struct stat st;
    if (stat(path, &st) == 0)
        return S_ISDIR(st.st_mode);
    return false;
}

uint calc_hashv(const void *ptr, size_t len) {
    uint hashv = 0;
    HASH_FUNCTION(ptr, len, hashv);
    return hashv;
}

bool has_aes(void) {
    bool found = false;

    FILE *f = fopen("/proc/cpuinfo", "r");
    if (!f) goto out;

    char buf[10];
    while (fscanf(f, "%9s", buf) > 0) {
        if (strstr(buf, "aes")) {
            found = true;
            break;
        }
    }

out:
    if (f) fclose(f);
    return found;
}
