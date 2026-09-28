#!/bin/sh
# Fail before replacing a service if the selected N64 build needs an absent FPU.
set -eu
case "${1:-}" in
    arm)
        if ! grep -Eq '^Features[[:space:]]*:.*[[:space:]](vfpv3|vfpv3d16|vfpv4|fp)([[:space:]]|$)' "${2:-/proc/cpuinfo}"; then
            echo 'ARMv7: this build requires VFPv3 or newer; installation cancelled' >&2
            exit 1
        fi
        ;;
    mips64el)
        if ! grep -Eq '^cpu model[[:space:]]*:.*[[:space:]]FPU([[:space:]]|$)' "${2:-/proc/cpuinfo}"; then
            echo 'MIPS64EL: this N64 build requires a hardware FPU; installation cancelled' >&2
            exit 1
        fi
        ;;
esac
