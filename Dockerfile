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
# git: let build.zig stamp the short commit id into the version string (needs .git mounted)
# wget/tar/autoconf/automake/libtool/make: only needed to build wolfssl for -Dwolfssl (DoT)
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl xz-utils git \
        wget tar autoconf automake libtool make \
    && rm -rf /var/lib/apt/lists/* \
    && git config --system --add safe.directory '*'

# install the pinned zig toolchain for this image's architecture
RUN set -eux; \
    arch="$(uname -m)"; \
    url="https://ziglang.org/download/${ZIG_VERSION}/zig-linux-${arch}-${ZIG_VERSION}.tar.xz"; \
    curl -fsSL "$url" -o /tmp/zig.tar.xz; \
    mkdir -p /opt/zig; \
    tar -xf /tmp/zig.tar.xz -C /opt/zig --strip-components=1; \
    rm /tmp/zig.tar.xz; \
    ln -s /opt/zig/zig /usr/local/bin/zig; \
    zig version

WORKDIR /src

# default to building; extra args from `docker run` are appended to `zig build`
ENTRYPOINT ["zig", "build"]
CMD []
