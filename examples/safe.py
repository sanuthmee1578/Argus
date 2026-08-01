"""Safe baseline demo.

Expected Argus behavior:
    SUCCESS

This script performs deterministic, CPU-light work and does not access the
network, spawn child processes, or allocate significant memory.
"""


def main() -> None:
    total = sum(range(10))
    print(f"safe demo completed: total={total}")


if __name__ == "__main__":
    main()
