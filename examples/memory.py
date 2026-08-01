"""Controlled memory-limit demo.

Expected Argus behavior with the default policy:
    MEMORY_LIMIT_EXCEEDED

The default policy memory limit is 100 MiB. This script allocates memory in
small chunks up to 128 MiB by default, which should cross that limit without
being an unbounded allocation loop. Pass one optional numeric argument to reduce
or increase the bounded allocation target.
"""

from __future__ import annotations

import sys
import time


DEFAULT_MEMORY_MB = 128
MAX_MEMORY_MB = 256
CHUNK_MB = 4


def bounded_int_from_argv(default: int, upper_bound: int) -> int:
    if len(sys.argv) < 2:
        return default

    try:
        value = int(sys.argv[1])
    except ValueError:
        return default

    return max(0, min(value, upper_bound))


def main() -> None:
    target_mb = bounded_int_from_argv(
        DEFAULT_MEMORY_MB,
        MAX_MEMORY_MB,
    )
    blocks = []

    for allocated_mb in range(0, target_mb, CHUNK_MB):
        blocks.append(bytearray(CHUNK_MB * 1024 * 1024))
        print(f"allocated {allocated_mb + CHUNK_MB} MiB")
        time.sleep(0.05)

    print(f"memory demo completed after allocating {target_mb} MiB")


if __name__ == "__main__":
    main()
