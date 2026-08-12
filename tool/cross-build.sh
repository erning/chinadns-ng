#!/bin/sh
set -eu

zig=${ZIG:-zig}
out=${OUT:-build/cross}

mkdir -p "$out"

sources='
src/main.c
src/core.c
src/config.c
src/server.c
src/cache.c
src/local_rr.c
src/dns.c
src/dnl.c
src/ipset.c
src/nl.c
src/net.c
src/tag.c
src/log.c
src/misc.c
'

if [ "$#" -gt 0 ]; then
    targets="$*"
else
    targets='
x86-linux-musl
x86_64-linux-musl
arm-linux-musleabi
arm-linux-musleabihf
aarch64-linux-musl
mips-linux-musleabi
mips-linux-musleabihf
mipsel-linux-musleabi
mipsel-linux-musleabihf
mips64-linux-muslabi64
mips64el-linux-muslabi64
riscv64-linux-musl
'
fi

for target in $targets; do
    echo "building $target"
    ZIG_GLOBAL_CACHE_DIR="${TMPDIR:-/tmp}/chinadns-ng-zig-$target" \
        "$zig" cc -target "$target" -DMUSL -Isrc -std=gnu11 -O2 -Wall -Wextra -static \
        $sources -o "$out/chinadns-ng-$target"
done
