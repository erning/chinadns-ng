# syntax=docker/dockerfile:1.7

# Reusable toolchain for building the complete static Linux release matrix.
FROM alpine:latest AS base

RUN apk add --no-cache \
        autoconf automake bash binutils curl libtool make zig \
    && zig version

COPY --chmod=755 tool/zig-reexec.sh /opt/zig_.sh
# Keep Alpine's current Zig, but make its internal Clang re-exec observable so
# the release script can correct MIPS soft-float compilation when requested.
RUN cp /usr/bin/zig /opt/zig_ \
    && sed -i 's@/proc/self/exe@/opt/zig123456@g' /opt/zig_ \
    && ln -s /opt/zig_.sh /opt/zig123456 \
    && ln -s /opt/zig_.sh /usr/local/bin/zig

ENV ZIG_LIB_DIR=/usr/lib/zig

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
