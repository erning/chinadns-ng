# syntax=docker/dockerfile:1.7

# Reusable toolchain for building the complete static Linux release matrix.
# Ubuntu 24.04 multi-architecture index, resolved on 2026-08-16. Match the
# GitHub Actions runner OS while retaining native amd64/arm64 Docker builds.
FROM --platform=$BUILDPLATFORM ubuntu:24.04@sha256:561618e2c15bf2397621dd04f96926663a3b5616c189cf7e38db7e82f5c538ea AS base

ARG BUILDARCH
ENV ZIG_VERSION=0.16.0

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        autoconf automake bash binutils ca-certificates curl libtool make tar xz-utils \
    && rm -rf /var/lib/apt/lists/*

COPY --chmod=755 tool/zig-reexec.sh /opt/zig-wrapper

# Install the official, checksum-pinned Zig toolchain for the native build
# platform. Make internal Clang re-exec observable so the release script can
# correct MIPS soft-float compilation when requested.
RUN case "$BUILDARCH" in \
        amd64) \
            zig_arch=x86_64; \
            zig_sha256=70e49664a74374b48b51e6f3fdfbf437f6395d42509050588bd49abe52ba3d00 \
            ;; \
        arm64) \
            zig_arch=aarch64; \
            zig_sha256=ea4b09bfb22ec6f6c6ceac57ab63efb6b46e17ab08d21f69f3a48b38e1534f17 \
            ;; \
        *) \
            echo "unsupported Docker build architecture: $BUILDARCH" >&2; \
            exit 1 \
            ;; \
    esac \
    && zig_archive=/tmp/zig.tar.xz \
    && curl -fL --retry 3 \
        "https://ziglang.org/download/$ZIG_VERSION/zig-$zig_arch-linux-$ZIG_VERSION.tar.xz" \
        -o "$zig_archive" \
    && echo "$zig_sha256  $zig_archive" | sha256sum --check --strict \
    && mkdir -p /opt/zig \
    && tar -xJf "$zig_archive" -C /opt/zig --strip-components=1 \
    && rm "$zig_archive" \
    && mv /opt/zig/zig /opt/zig/zig-real \
    && sed -i 's@/proc/self/exe@/opt/zig123456@g' /opt/zig/zig-real \
    && grep -a -q '/opt/zig123456' /opt/zig/zig-real \
    && ln -s /opt/zig-wrapper /opt/zig123456 \
    && ln -s /opt/zig-wrapper /usr/local/bin/zig

ENV ZIG_LIB_DIR=/opt/zig/lib \
    ZIG_REAL=/opt/zig/zig-real

RUN test "$(zig version)" = "$ZIG_VERSION"

COPY --chmod=755 tool/release-build.sh /usr/local/bin/chinadns-release-build

WORKDIR /src

ENTRYPOINT ["chinadns-release-build"]
CMD []


# BuildKit target for exporting binaries without first creating a builder image.
FROM base AS build

ARG TARGETS=""
ARG FLAVORS="plain wolfssl"
ARG NOASM=1
ARG WOLFSSL_VERSION=5.8.2
ENV OUT=/out
ENV CACHE_DIR=/build-cache
ENV TARGETS=$TARGETS
ENV FLAVORS=$FLAVORS
ENV NOASM=$NOASM
ENV WOLFSSL_VERSION=$WOLFSSL_VERSION

COPY . .

RUN --mount=type=cache,target=/build-cache chinadns-release-build


FROM scratch AS artifacts

COPY --from=build /out/ /


# Keep the reusable toolchain as the Dockerfile's default target.
FROM base AS toolchain
