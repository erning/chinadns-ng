# Toolchain image for building / cross-compiling chinadns-ng with the pinned
# Zig 0.10.1 (this project relies on stage1 async and cannot use newer Zig).
#
# chinadns-ng is Linux-only (epoll / netlink), so on macOS or Windows this is
# the simplest way to build it. The image only ships the toolchain; the source
# is bind-mounted at /src, so the binary lands in ./zig-out/bin/ on the host.
#
# 1) Build the builder image once:
#      docker build -t chinadns-ng-builder .
#
# 2) Compile (any `zig build` args are forwarded, e.g. -Dtarget / -Dcpu / -Dwolfssl):
#      docker run --rm -v "$PWD":/src chinadns-ng-builder                              # native (this image's arch), glibc
#      docker run --rm -v "$PWD":/src chinadns-ng-builder -Dtarget=x86_64-linux-musl   # static musl
#      docker run --rm -v "$PWD":/src chinadns-ng-builder -Dtarget=aarch64-linux-musl
#      docker run --rm -v "$PWD":/src chinadns-ng-builder -Dwolfssl -Dtarget=x86_64-linux-musl  # DoT (downloads wolfssl, needs network)
#      docker run --rm -v "$PWD":/src chinadns-ng-builder clean-all                    # any build step works too
#
#    The binary is written to ./zig-out/bin/ (named after the target/cpu/mode).
#
# Notes:
#  - On Linux hosts add  --user "$(id -u):$(id -g)"  to avoid root-owned artifacts
#    (build.zig keeps its cache inside ./zig-cache, so no extra cache dir is needed).
#  - For a shell instead of a build:  docker run --rm -it -v "$PWD":/src --entrypoint sh chinadns-ng-builder
#  - Override the Zig version with  --build-arg ZIG_VERSION=0.10.1  (must stay 0.10.x).

FROM debian:12-slim

ARG ZIG_VERSION=0.10.1

# ca-certificates/curl/xz: fetch the zig toolchain
# minisign: verify that toolchain against zig's pinned official public key
# git: let build.zig stamp the short commit id into the version string (needs .git mounted)
# patch: apply the mips64 std-lib patches to the pinned zig (see below)
# wget/tar/autoconf/automake/libtool/make: only needed to build wolfssl for -Dwolfssl (DoT)
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl xz-utils git patch minisign \
        wget tar autoconf automake libtool make \
    && rm -rf /var/lib/apt/lists/* \
    && git config --system --add safe.directory '*'

# install the pinned zig toolchain for this image's architecture, after verifying its
# minisign signature against zig's official public key (pinned below as the trust anchor,
# published at https://ziglang.org/download/). this is arch-independent and proves the
# tarball's authenticity, not just its integrity.
RUN set -eux; \
    arch="$(uname -m)"; \
    url="https://ziglang.org/download/${ZIG_VERSION}/zig-linux-${arch}-${ZIG_VERSION}.tar.xz"; \
    curl -fsSL "$url" -o /tmp/zig.tar.xz; \
    curl -fsSL "$url.minisig" -o /tmp/zig.tar.xz.minisig; \
    minisign -Vm /tmp/zig.tar.xz \
        -P 'RWSGOq2NVecA2UPNdBUZykf1CCb147pkmdtYxgb3Ti+JO/wCYvhbAb/U'; \
    mkdir -p /opt/zig; \
    tar -xf /tmp/zig.tar.xz -C /opt/zig --strip-components=1; \
    rm /tmp/zig.tar.xz /tmp/zig.tar.xz.minisig; \
    ln -s /opt/zig/zig /usr/local/bin/zig; \
    zig version

# [1] add mips64/mips64el support to the pinned zig (upstream PRs #14541 + #14556, which
# never landed in 0.10.1). they touch lib/std only, so no compiler rebuild is needed;
# applied with `patch --fuzz` since 0.10.1's context differs slightly from the PRs' base.
# #14556 also edits tools/generate_linux_syscalls.zig, which the release tarball does not
# ship, so that file's diff is stripped. without these, mips64/mips64el fail inside std.
# the downloaded patches are pinned by sha256: GitHub's PR .patch endpoints are mutable
# (a force-push to the PR branch changes them), so verify before applying. to refresh,
# re-download and update the hashes:  curl -fsSL <url> | sha256sum
RUN set -eux; \
    cd /opt/zig; \
    base="https://github.com/ziglang/zig/pull"; \
    curl -fsSL "$base/14541.patch" -o /tmp/14541.patch; \
    curl -fsSL "$base/14556.patch" -o /tmp/14556.patch; \
    echo "4ee95bebeb510b280cb609c456d54e63339cc5cceaaf5e42e8d9e7a86357bc07  /tmp/14541.patch" | sha256sum -c -; \
    echo "2ee66c7159f805e43f2c7d345de718882f4d1f2286b1833e2144b2c916e8257f  /tmp/14556.patch" | sha256sum -c -; \
    patch -p1 --fuzz=3 --forward < /tmp/14541.patch; \
    sed '/^diff --git a\/tools\//,$d' /tmp/14556.patch | patch -p1 --fuzz=3 --forward; \
    test -f lib/std/os/linux/mips64.zig; \
    rm -f /tmp/14541.patch /tmp/14556.patch

# [2] fix soft-float mips (https://www.zfl9.com/zig-mips.html). zig 0.10.1 forgets to pass
# -msoft-float when assembling musl's .s/.S files, so they get a hard-float ABI and fail to
# link against a -msoft-float target. instead of rebuilding zig, intercept its internal
# clang calls: zig re-execs itself via the string "/proc/self/exe"; rewrite that (in a copy
# `zig_`) to a same-length path that points at a wrapper which appends -march/-msoft-float
# for mips asm. the wrapper reads MIPS_M_ARCH / MIPS_SOFT_FP (set per-target by the build).
RUN set -eux; \
    cd /opt/zig; \
    cp -af zig zig_; \
    sed -i 's@/proc/self/exe@/opt/zig123456@g' zig_; \
    printf '%s\n' \
      '#!/bin/bash' \
      'argv=("$@")' \
      'if [ "$MIPS_M_ARCH" ] && [ "${argv[0]}" = clang ] && [[ "${argv[1]}" == *.s || "${argv[1]}" == *.S || "${argv[1]}" == *.sx ]] && [[ "${argv[*]}" == *" -target mips"* ]]; then' \
      '    argv+=("-march=$MIPS_M_ARCH")' \
      '    ((MIPS_SOFT_FP)) && argv+=("-msoft-float")' \
      'fi' \
      'exec zig_ "${argv[@]}"' \
      > zig_.sh; \
    chmod +x zig_.sh; \
    ln -snf /opt/zig/zig_.sh /opt/zig123456; \
    ln -snf /opt/zig/zig_    /usr/local/bin/zig_; \
    ln -snf /opt/zig/zig_.sh /usr/local/bin/zig

WORKDIR /src

# default to building; extra args from `docker run` are appended to `zig build`
ENTRYPOINT ["zig", "build"]
CMD []
