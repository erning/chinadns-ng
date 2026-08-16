#!/bin/bash
set -e

args=("$@")

# Zig 0.16 does not forward its MIPS soft_float CPU feature to every internal
# Clang invocation. In particular, musl assembly files otherwise retain a
# hard-float ABI and cannot be linked into a soft-float executable.
if [ "${MIPS_SOFT_FP:-0}" = 1 ] && [ "${args[0]:-}" = clang ] \
    && [[ " ${args[*]} " == *" -target mips"* ]]; then
    args+=("-msoft-float")
fi

exec "${ZIG_REAL:-/opt/zig/zig-real}" "${args[@]}"
