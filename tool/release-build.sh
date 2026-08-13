#!/bin/sh
set -eu

if [ -f src/main.c ]; then
    :
else
    cd "$(dirname "$0")/.."
fi
root=$PWD

zig=${ZIG:-zig}
out=${OUT:-build/release}
cache=${CACHE_DIR:-build/.release-cache}
targets=${TARGETS:-}
flavors=${FLAVORS:-"plain wolfssl"}
noasm=${NOASM:-1}
wolfssl_version=${WOLFSSL_VERSION:-5.8.2}
jobs=${JOBS:-}

if [ "$#" -gt 0 ]; then
    targets="$*"
fi

if [ -z "$jobs" ]; then
    jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)
fi

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

# target|cpu|output cpu label
matrix='
aarch64-linux-musl|generic+v8a|generic+v8a
aarch64-linux-musl|generic+v9a|generic+v9a
arm-linux-musleabi|generic+v5t+soft_float|generic+v5t+soft_float
arm-linux-musleabi|generic+v5te+soft_float|generic+v5te+soft_float
arm-linux-musleabi|generic+v6+soft_float|generic+v6+soft_float
arm-linux-musleabi|generic+v6t2+soft_float|generic+v6t2+soft_float
arm-linux-musleabi|generic+v7a|generic+v7a
arm-linux-musleabihf|generic+v7a|generic+v7a
i386-linux-musl|i686|i686
i386-linux-musl|pentium4|pentium4
mips-linux-musl|mips32|mips32
mips-linux-musl|mips32+soft_float|mips32+soft_float
mips64-linux-musl|mips64|mips64
mips64-linux-musl|mips64+soft_float|mips64+soft_float
mips64el-linux-musl|mips64|mips64
mips64el-linux-musl|mips64+soft_float|mips64+soft_float
mipsel-linux-musl|mips32|mips32
mipsel-linux-musl|mips32+soft_float|mips32+soft_float
riscv64-linux-musl||baseline_rv64
x86_64-linux-musl|x86_64|x86_64
x86_64-linux-musl|x86_64_v2|x86_64_v2
x86_64-linux-musl|x86_64_v3|x86_64_v3
x86_64-linux-musl|x86_64_v4|x86_64_v4
'

has_flavor() {
    wanted=$1
    for item in $flavors; do
        [ "$item" = "$wanted" ] && return 0
    done
    return 1
}

target_selected() {
    matrix_target=$1
    matrix_cpu=$2
    [ -z "$targets" ] && return 0
    for filter in $targets; do
        case "$matrix_target@$matrix_cpu" in
            *"$filter"*) return 0 ;;
        esac
    done
    return 1
}

download() {
    url=$1
    destination=$2
    if command -v curl >/dev/null 2>&1; then
        curl -fL --retry 3 "$url" -o "$destination"
    elif command -v wget >/dev/null 2>&1; then
        wget "$url" -O "$destination"
    else
        echo "curl or wget is required to download wolfSSL" >&2
        exit 1
    fi
}

prepare_wolfssl() {
    wolfssl_source="$cache/wolfssl-$wolfssl_version-stable"
    [ -x "$wolfssl_source/configure" ] && return

    mkdir -p "$cache"
    wolfssl_archive="$cache/wolfssl-$wolfssl_version-stable.tar.gz"
    if [ ! -f "$wolfssl_archive" ]; then
        echo "downloading wolfSSL $wolfssl_version"
        download \
            "https://github.com/wolfSSL/wolfssl/archive/refs/tags/v$wolfssl_version-stable.tar.gz" \
            "$wolfssl_archive"
    fi

    rm -rf "$wolfssl_source"
    tar -xzf "$wolfssl_archive" -C "$cache"
    (cd "$wolfssl_source" && ./autogen.sh)
}

compile_target() {
    target=$1
    cpu=$2
    case $target in
        i386-linux-musl) echo x86-linux-musl ;;
        mips-linux-musl)
            case $cpu in *+soft_float) echo mips-linux-musleabi ;; *) echo mips-linux-musleabihf ;; esac
            ;;
        mipsel-linux-musl)
            case $cpu in *+soft_float) echo mipsel-linux-musleabi ;; *) echo mipsel-linux-musleabihf ;; esac
            ;;
        mips64-linux-musl) echo mips64-linux-muslabi64 ;;
        mips64el-linux-musl) echo mips64el-linux-muslabi64 ;;
        *) echo "$target" ;;
    esac
}

build_wolfssl() {
    target=$1
    cpu=$2
    disable_accel=$3
    compat_key=
    case "$target@$cpu" in
        mips*-linux-musl@*+soft_float) compat_key=@softfp-v1 ;;
    esac
    key=$(printf '%s' "$wolfssl_version@$target@$cpu@noasm=$disable_accel$compat_key" | tr '/@+=' '_____')
    wolfssl_prefix="$cache/wolfssl-install-$key"
    [ -f "$wolfssl_prefix/lib/libwolfssl.a" ] && return

    prepare_wolfssl

    wolfssl_build="$cache/wolfssl-build-$key"
    rm -rf "$wolfssl_build" "$wolfssl_prefix"
    mkdir -p "$wolfssl_build" "$wolfssl_prefix"

    zig_target=$(compile_target "$target" "$cpu")
    wolfssl_cc="$zig cc -target $zig_target"
    [ -n "$cpu" ] && wolfssl_cc="$wolfssl_cc -mcpu=$cpu"

    mips_soft_fp=0
    wolfssl_lto=-flto
    case "$target@$cpu" in
        mips*-linux-musl@*+soft_float) mips_soft_fp=1 ;;
    esac
    case "$target@$cpu" in
        mips64*-linux-musl@*+soft_float) wolfssl_lto= ;;
    esac

    aesni=
    intelasm=
    armasm=
    asm=--enable-asm
    sha512=--disable-sha512
    extra_cflags=

    case $target in
        x86_64-*) aesni=--enable-aesni ;;
        aarch64-*) sha512=--enable-sha512 ;;
        mips64-*|mips64el-*) asm=--disable-asm ;;
    esac
    if [ "$disable_accel" != 1 ]; then
        case $cpu in
            x86_64_v3|x86_64_v4) intelasm=--enable-intelasm ;;
        esac
        case $target in
            aarch64-*) armasm=--enable-armasm ;;
        esac
    fi
    case $cpu in
        generic+v5t*|generic+v5te*) extra_cflags=-DWOLFSSL_NO_FENCE ;;
    esac

    echo "building wolfSSL $target@${cpu:-default} (noasm=$disable_accel)"
    (
        cd "$wolfssl_build"
        export CC="$wolfssl_cc"
        export AR="$zig ar"
        export RANLIB="$zig ranlib"
        export MIPS_SOFT_FP="$mips_soft_fp"
        export ZIG_GLOBAL_CACHE_DIR="$cache/zig-$key"
        CFLAGS="-O3 -g0 $wolfssl_lto -fno-pie -fno-PIE -ffunction-sections -fdata-sections -include $root/tool/wolfssl-options.h $extra_cflags" \
            "$wolfssl_source/configure" \
                --host="$target" \
                --prefix="$wolfssl_prefix" \
                --enable-static \
                --disable-shared \
                --disable-harden \
                --disable-ocsp \
                --disable-oldnames \
                --enable-sys-ca-certs \
                --disable-memory \
                --disable-staticmemory \
                --enable-singlethreaded \
                --disable-threadlocal \
                --disable-asyncthreads \
                --disable-errorqueue \
                --disable-error-queue-per-thread \
                --disable-openssl-compatible-defaults \
                --disable-opensslextra \
                --disable-opensslall \
                --disable-dtls \
                --disable-oldtls \
                --enable-tls13 \
                --enable-chacha \
                --enable-poly1305 \
                --enable-aesgcm \
                --disable-aescbc \
                --enable-sni \
                --disable-session-ticket \
                --disable-md5 \
                --disable-sha \
                --disable-sha3 \
                --disable-sha224 \
                "$sha512" \
                --disable-pkcs7 \
                --disable-pkcs8 \
                --disable-pkcs11 \
                --disable-pkcs12 \
                --disable-dh \
                --enable-ecc \
                --enable-rsa \
                --disable-oaep \
                --enable-coding \
                --disable-base64encode \
                --disable-asn-print \
                --disable-pwdbased \
                --disable-secure-renegotiation-info \
                --disable-crypttests \
                --disable-benchmark \
                --disable-examples \
                $aesni $intelasm $armasm "$asm"
        make -j"$jobs" install
    )
}

verify_binary() {
    binary=$1
    target=$2
    cpu=$3

    readelf -h "$binary" >/dev/null
    if readelf -l "$binary" | grep -q 'INTERP'; then
        echo "dynamic executable produced unexpectedly: $binary" >&2
        exit 1
    fi
    case "$target@$cpu" in
        mips*-linux-musl@*+soft_float)
            if ! readelf -A "$binary" | grep -q 'FP ABI: Soft float'; then
                echo "soft-float ABI verification failed: $binary" >&2
                exit 1
            fi
            ;;
    esac
}

build_chinadns() {
    target=$1
    cpu=$2
    cpu_label=$3
    flavor=$4
    disable_accel=${5:-0}
    zig_target=$(compile_target "$target" "$cpu")

    mips_soft_fp=0
    lto=-flto
    mode=fast+lto
    cache_suffix=
    case "$target@$cpu" in
        mips*-linux-musl@*+soft_float)
            mips_soft_fp=1
            cache_suffix=-softfp-v1
            ;;
    esac
    case "$target@$cpu" in
        mips64*-linux-musl@*+soft_float) lto=; mode=fast ;;
    esac

    case $flavor in
        plain) name="chinadns-ng@$target@$cpu_label@$mode" ;;
        wolfssl) name="chinadns-ng+wolfssl@$target@$cpu_label@$mode" ;;
        wolfssl_noasm) name="chinadns-ng+wolfssl_noasm@$target@$cpu_label@$mode" ;;
        *) echo "unknown flavor: $flavor" >&2; exit 2 ;;
    esac

    set -- -target "$zig_target"
    [ -n "$cpu" ] && set -- "$@" -mcpu="$cpu"

    compatibility_source=
    case $cpu in
        generic+v5t*|generic+v5te*) compatibility_source=tool/armv5-atomics.c ;;
    esac

    echo "building $name"
    if [ "$flavor" = plain ]; then
        MIPS_SOFT_FP="$mips_soft_fp" \
        ZIG_GLOBAL_CACHE_DIR="$cache/zig-project-$target-$cpu_label$cache_suffix" \
            "$zig" cc "$@" -DMUSL -Isrc -std=gnu11 -O3 $lto -s -static \
                -Wall -Wextra -fno-strict-aliasing -ffunction-sections -fdata-sections \
                -Wl,--gc-sections $sources $compatibility_source -o "$out/$name"
    else
        build_wolfssl "$target" "$cpu" "$disable_accel"
        MIPS_SOFT_FP="$mips_soft_fp" \
        ZIG_GLOBAL_CACHE_DIR="$cache/zig-project-$target-$cpu_label-$flavor$cache_suffix" \
            "$zig" cc "$@" -DMUSL -DENABLE_WOLFSSL -Isrc \
                -I"$wolfssl_prefix/include" -std=gnu11 -O3 $lto -s -static \
                -Wall -Wextra -fno-strict-aliasing -ffunction-sections -fdata-sections \
                -Wl,--gc-sections $sources $compatibility_source \
                -L"$wolfssl_prefix/lib" -lwolfssl -lm \
                -o "$out/$name"
    fi
    verify_binary "$out/$name" "$target" "$cpu"
}

case " $flavors " in
    *" plain "*|*" wolfssl "*) ;;
    *) echo "FLAVORS must contain plain and/or wolfssl" >&2; exit 2 ;;
esac

mkdir -p "$out" "$cache"

printf '%s\n' "$matrix" | while IFS='|' read -r target cpu cpu_label; do
    [ -n "$target" ] || continue
    target_selected "$target" "$cpu" || continue

    has_flavor plain && build_chinadns "$target" "$cpu" "$cpu_label" plain
    if has_flavor wolfssl; then
        build_chinadns "$target" "$cpu" "$cpu_label" wolfssl 0
        if [ "$noasm" = 1 ] && [ "$target" = aarch64-linux-musl ] \
            && [ "$cpu" = generic+v8a ]; then
            build_chinadns "$target" "$cpu" "$cpu_label" wolfssl_noasm 1
        fi
    fi
done

(
    cd "$out"
    sha256sum chinadns-ng* > SHA256SUMS
)
