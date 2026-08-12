#!/bin/sh
set -eu

cc=${CC:-cc}
cflags=${CFLAGS:--O3 -s}
project_cflags='-std=gnu11 -Wall -Wextra -Wvla -fno-strict-aliasing -ffunction-sections -fdata-sections -Wl,--gc-sections'
OBJS='dns_cache_mgr.c ../src/dns.c'
MAIN='dns_cache_mgr'

for arg in "$@"; do
    case $arg in
        CC=*) cc=${arg#CC=} ;;
        CFLAGS=*) cflags=${arg#CFLAGS=} ;;
        *) echo "unsupported argument: $arg" >&2; exit 2 ;;
    esac
done

set -x

$cc $cflags $project_cflags $OBJS -o $MAIN
