#!/usr/bin/env bash
#
# Build the chinadns-ng release matrix (static musl binaries for every target)
# inside the pinned zig 0.10.1 Docker toolchain, reproducing the per-target
# assets published on the GitHub releases page.
#
# Each binary is named by build.zig exactly like the release asset, e.g.
#   chinadns-ng@x86_64-linux-musl@x86_64_v3@fast+lto
#   chinadns-ng+wolfssl@aarch64-linux-musl@generic+v8a@fast+lto
#   chinadns-ng+wolfssl_noasm@aarch64-linux-musl@generic+v8a@fast+lto
#
# Usage:
#   tool/build-release.sh [filter]
#     filter   optional substring; only build entries whose "<target>@<cpu>"
#              contains it (e.g. "x86_64", "aarch64", "mips64-linux-musl@mips64")
#
# Env overrides:
#   IMAGE        builder image tag             (default: chinadns-ng-builder:0.10.1)
#   OUT_DIR      output directory              (default: release/<version>)
#   FLAVORS      space-separated flavor list   (default: "plain wolfssl")
#   NOASM        also build wolfssl_noasm for aarch64+v8a (default: 1)
#   BUILD_IMAGE  force (re)build the image     (default: 0; auto-builds if absent)
#
# Notes:
#   * Needs the Docker daemon running. The image is built from ./Dockerfile
#     (pinned zig 0.10.1) if it is missing.
#   * wolfssl builds download + compile wolfssl on first use per target/cpu and
#     therefore need network access inside the container; results are cached in
#     ./dep so re-runs are fast.
#   * mips relies on fixes baked into the Docker image: PRs #14541/#14556 add
#     mips64/mips64el std support, and a soft-float wrapper (zig-mips.html) makes
#     -msoft-float reach musl's asm. With those, every mips target builds (hard and
#     soft float); this script passes MIPS_M_ARCH / MIPS_SOFT_FP per target so the
#     wrapper kicks in. Caveat: zig's cache key ignores the wrapper's injected
#     flags, so if a soft_float mips target was once built without the wrapper, do
#     one `rm -rf zig-cache` to drop the stale hard-float musl objects.
#
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT=$PWD

IMAGE=${IMAGE:-chinadns-ng-builder:0.10.1}
VERSION=$(sed -nE 's/^const chinadns_version = "([^"]+)".*/\1/p' build.zig)
OUT_DIR=${OUT_DIR:-release/${VERSION:-snapshot}}
FLAVORS=${FLAVORS:-"plain wolfssl"}
NOASM=${NOASM:-1}
BUILD_IMAGE=${BUILD_IMAGE:-0}
FILTER=${1:-}

HOSTOS=$(uname -s)

# "<target>|<cpu>|<docker-env...>"   (empty cpu => let zig pick the default)
MATRIX=(
    "aarch64-linux-musl|generic+v8a|"
    "aarch64-linux-musl|generic+v9a|"
    "arm-linux-musleabi|generic+v5t+soft_float|"
    "arm-linux-musleabi|generic+v5te+soft_float|"
    "arm-linux-musleabi|generic+v6+soft_float|"
    "arm-linux-musleabi|generic+v6t2+soft_float|"
    "arm-linux-musleabi|generic+v7a|"
    "arm-linux-musleabihf|generic+v7a|"
    "i386-linux-musl|i686|"
    "i386-linux-musl|pentium4|"
    "mips-linux-musl|mips32|MIPS_M_ARCH=mips32"
    "mips-linux-musl|mips32+soft_float|MIPS_M_ARCH=mips32 MIPS_SOFT_FP=1"
    "mips64-linux-musl|mips64|MIPS_M_ARCH=mips64"
    "mips64-linux-musl|mips64+soft_float|MIPS_M_ARCH=mips64 MIPS_SOFT_FP=1"
    "mips64el-linux-musl|mips64|MIPS_M_ARCH=mips64"
    "mips64el-linux-musl|mips64+soft_float|MIPS_M_ARCH=mips64 MIPS_SOFT_FP=1"
    "mipsel-linux-musl|mips32|MIPS_M_ARCH=mips32"
    "mipsel-linux-musl|mips32+soft_float|MIPS_M_ARCH=mips32 MIPS_SOFT_FP=1"
    "riscv64-linux-musl||"
    "x86_64-linux-musl|x86_64|"
    "x86_64-linux-musl|x86_64_v2|"
    "x86_64-linux-musl|x86_64_v3|"
    "x86_64-linux-musl|x86_64_v4|"
)

# ----------------------------------------------------------------------------

die() { echo "error: $*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || die "docker not found in PATH"
docker version >/dev/null 2>&1 || die "docker daemon is not running"

if [ "$BUILD_IMAGE" = 1 ] || ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo ">> building toolchain image: $IMAGE"
    docker build -t "$IMAGE" "$ROOT"
fi

mkdir -p "$OUT_DIR"
LOGDIR=$(mktemp -d)
ok=(); failed=()

run_build() {
    local target=$1 cpu=$2 envs=$3 flavor=$4

    local -a dflags=( "-Dtarget=$target" )
    [ -n "$cpu" ] && dflags+=( "-Dcpu=$cpu" )
    dflags+=( "-Dlto" )
    case $flavor in
        plain)         ;;
        wolfssl)       dflags+=( "-Dwolfssl" ) ;;
        wolfssl_noasm) dflags+=( "-Dwolfssl" "-Dwolfssl-noasm" ) ;;
        *)             die "unknown flavor: $flavor" ;;
    esac

    local -a eflags=()
    local kv; for kv in $envs; do eflags+=( -e "$kv" ); done
    [ "$HOSTOS" = Linux ] && eflags+=( --user "$(id -u):$(id -g)" )

    local label="$flavor:$target@${cpu:-default}"
    local log="$LOGDIR/$(echo "$label" | tr '/:@+ ' '_____').log"

    rm -rf "$ROOT/zig-out/bin"
    printf '  %-58s ' "$label"
    if docker run --rm -v "$ROOT":/src "${eflags[@]}" "$IMAGE" "${dflags[@]}" >"$log" 2>&1; then
        local bin
        bin=$(ls "$ROOT/zig-out/bin" 2>/dev/null | head -1 || true)
        if [ -n "$bin" ]; then
            mv -f "$ROOT/zig-out/bin/$bin" "$OUT_DIR/$bin"
            echo "ok"
            ok+=("$bin")
        else
            echo "FAIL (no output, see $log)"
            failed+=("$label")
        fi
    else
        echo "FAIL (see $log)"
        failed+=("$label")
    fi
}

echo ">> chinadns-ng $VERSION  ->  $OUT_DIR   (flavors: $FLAVORS${FILTER:+, filter: $FILTER})"

for entry in "${MATRIX[@]}"; do
    IFS='|' read -r target cpu envs <<<"$entry"
    if [ -n "$FILTER" ] && [[ "$target@$cpu" != *"$FILTER"* ]]; then
        continue
    fi
    for fl in $FLAVORS; do
        run_build "$target" "$cpu" "$envs" "$fl"
    done
    # the release ships one extra: wolfssl without asm accel for aarch64+v8a
    if [ "$NOASM" = 1 ] && [ "$target" = aarch64-linux-musl ] && [ "$cpu" = "generic+v8a" ] \
        && [[ " $FLAVORS " == *" wolfssl "* ]]; then
        run_build "$target" "$cpu" "$envs" wolfssl_noasm
    fi
done

# checksums (best effort)
if [ ${#ok[@]} -gt 0 ]; then
    ( cd "$OUT_DIR"
      if command -v sha256sum >/dev/null 2>&1; then sha256sum -- chinadns-ng* > SHA256SUMS
      elif command -v shasum   >/dev/null 2>&1; then shasum -a 256 -- chinadns-ng* > SHA256SUMS
      fi ) || true
fi

echo
echo ">> done: ${#ok[@]} built, ${#failed[@]} failed  ->  $OUT_DIR"
if [ ${#failed[@]} -gt 0 ]; then
    printf '   FAILED: %s\n' "${failed[@]}"
    exit 1
fi
