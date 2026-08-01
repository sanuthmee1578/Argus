"""Controlled timeout demo.

Expected Argus behavior with the default policy:
    TIMEOUT

The default policy timeout is 15 seconds. This script sleeps for 20 seconds by
default, which is long enough to trigger the timeout but still bounded when run
directly. Pass one optional numeric argument for local experiments.
"""

from __future__ import annotations

import sys
import time


DEFAULT_SLEEP_SECONDS = 20
MAX_SLEEP_SECONDS = 60


def bounded_int_from_argv(default: int, upper_bound: int) -> int:
    if len(sys.argv) < 2:
        return default

    try:
        value = int(sys.argv[1])
    except ValueError:
        return default

    return max(0, min(value, upper_bound))


def main() -> None:
    sleep_seconds = bounded_int_from_argv(
        DEFAULT_SLEEP_SECONDS,
        MAX_SLEEP_SECONDS,
    )
    print(f"sleeping for {sleep_seconds} seconds")
    time.sleep(sleep_seconds)
    print("timeout demo completed")


if __name__ == "__main__":
    main()
