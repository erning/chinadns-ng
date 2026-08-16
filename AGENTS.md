# Repository Instructions for Coding Agents

## Project Scope

This repository maintains the Pure C Linux implementation of chinadns-ng.
Keep the implementation in C and preserve Linux support, including static
musl cross-builds for the release target matrix.

The `origin` remote is the maintained fork. The `upstream` remote tracks the
original project. Do not mix Pure C development into the branches that mirror
upstream.

## Branch Model

- `master` and `dev` mirror the corresponding `upstream` branches. Do not put
  fork-specific Pure C work on them.
- `c/dev` is the integration branch for all Pure C development. Create feature
  and fix branches from `c/dev`, and merge them back into `c/dev`.
- `c/master` is release-only. Its tip must always be a published or
  release-ready stable version.
- Never commit development changes directly to `c/master`.
- Update `c/master` from `c/dev` with `git merge --ff-only c/dev`. If a
  fast-forward is not possible, stop and resolve the branch history instead of
  creating a merge commit.
- The GitHub default branch is `c/master`, but development pull requests must
  target `c/dev`.

## Version Rules

`CHINADNS_VERSION` in `src/core.h` is the source of truth.

- Stable releases use `YYYY.MM.DD-c`.
- Additional stable releases on the same date use `YYYY.MM.DD-c.N`, starting
  with `.1`. Do not add `.1` to the first stable release of a date.
- Normal development uses `YYYY.MM.DD-c-dev`.
- Published development snapshots use `YYYY.MM.DD-c-dev.N`, starting with
  `.1`. Do not increment the snapshot number for every ordinary commit.
- The development date normally remains the date of the latest stable Pure C
  release. Set the actual release date in the release preparation commit.
- Tags must exactly match the stable `CHINADNS_VERSION`. Never create a stable
  tag from a commit whose version contains `-dev`.

Prepare a release in this order:

1. Finish and test all release work on `c/dev`.
2. On `c/dev`, change `CHINADNS_VERSION` to the final stable version and commit
   the release preparation.
3. Fast-forward `c/master` to the tested `c/dev` commit.
4. Create an annotated tag with the exact stable version, then push
   `c/master` and the tag.
5. Return to `c/dev` and commit the next development version before resuming
   development.

The release workflow validates stable versions and tag equality. The
development workflow validates the `-dev` version form on pushes and pull
requests targeting `c/dev`.

## Build and Test

The program is Linux-only. On Linux, use the native build and end-to-end test:

```sh
make -j"$(nproc)"
make check
```

macOS cannot build or run the Linux program natively. Use Docker there. A
representative release-toolchain smoke build is:

```sh
targets='arm-linux-musleabi@generic+v5t+soft_float'
targets="$targets mipsel-linux-musl@mips32+soft_float"
targets="$targets aarch64-linux-musl@generic+v8a"

docker build \
  --target artifacts \
  --build-arg "TARGETS=$targets" \
  --output type=local,dest=build/docker-smoke \
  .
```

Use the complete Docker release matrix before publishing a stable release:

```sh
docker build \
  --target artifacts \
  --output type=local,dest=build/docker \
  .
```

Read `BUILD.md` before changing Docker, Zig, cross-compilation, wolfSSL, target
selection, or artifact validation behavior. Preserve the pinned Ubuntu base
image, pinned Zig version and checksums, and the MIPS soft-float workaround
unless the replacement is tested across the affected targets.

## Code and Change Guidelines

- Follow the existing GNU C11 style, four-space indentation, and brace layout.
- Keep builds clean under `-Wall -Wextra` and avoid strict-aliasing violations.
- Add or update `tests/e2e.py` coverage for behavior changes when practical.
- Do not commit generated binaries, build directories, caches, or downloaded
  dependency sources.
- Keep user-facing build instructions in `BUILD.md`; keep the README concise.
- Preserve unrelated worktree changes. Do not rewrite, discard, or reformat
  code outside the task scope.

## Commit Messages

Use an English ASCII Conventional Commit subject with a lowercase scope and an
imperative description, followed by a useful body after one blank line. Keep
body lines at 80 columns or fewer. Do not add authorship or tool attribution.

Example:

```text
fix(server): reject replies from unknown peers

Validate the sender before accepting a pending UDP response so spoofed
datagrams cannot complete another upstream's query.
```
