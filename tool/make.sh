#!/bin/sh
set -eu

cc=${CC:-cc}
cflags=${CFLAGS:--std=gnu11 -Wall -Wextra -Wvla -O3 -fno-strict-aliasing -ffunction-sections -fdata-sections -Wl,--gc-sections -s}
OBJS='dns_cache_mgr.c ../src/dns.c'
MAIN='dns_cache_mgr'

set -x

$cc $cflags $OBJS -o $MAIN
