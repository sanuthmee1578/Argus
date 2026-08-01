"""Controlled suspicious-pattern demo.

Expected Argus behavior with the default policy:
    BLOCKED_BY_POLICY when strict mode is enabled

The script contains an os.system call so Argus can demonstrate static policy
detection. If policy allows execution, the command is harmless and only prints a
short message.
"""

from __future__ import annotations

import os


def main() -> None:
    exit_code = os.system("printf 'suspicious demo command executed\\n'")
    print(f"command exit code: {exit_code}")


if __name__ == "__main__":
    main()
