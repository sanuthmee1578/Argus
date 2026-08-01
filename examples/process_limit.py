"""Controlled process-limit demo.

Expected Argus behavior with the default policy:
    SUCCESS with visible fork failure once pids.max is reached

This is a bounded process-spawning demo. It starts a limited number of
short-lived child processes and waits for each one. It is not an uncontrolled
process-spawning payload.
"""

from __future__ import annotations

import os
import sys
import time


DEFAULT_CHILDREN = 48
MAX_CHILDREN = 64
CHILD_SLEEP_SECONDS = 8


def bounded_int_from_argv(default: int, upper_bound: int) -> int:
    if len(sys.argv) < 2:
        return default

    try:
        value = int(sys.argv[1])
    except ValueError:
        return default

    return max(0, min(value, upper_bound))


def main() -> None:
    child_count = bounded_int_from_argv(
        DEFAULT_CHILDREN,
        MAX_CHILDREN,
    )
    children = []

    print(f"starting up to {child_count} child processes", flush=True)
    for index in range(child_count):
        try:
            pid = os.fork()
        except OSError as exc:
            print(f"fork failed at child {index}: {exc}", flush=True)
            break

        if pid == 0:
            time.sleep(CHILD_SLEEP_SECONDS)
            raise SystemExit(0)

        children.append(pid)
        print(f"started child {index + 1}: pid={pid}", flush=True)

    for pid in children:
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass

    print(f"process-limit demo completed: children_started={len(children)}", flush=True)


if __name__ == "__main__":
    main()
