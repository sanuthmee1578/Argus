"""Controlled runtime network-enforcement demo.

Expected Argus behavior with the default policy:
    SECURITY_VIOLATION

This script is scanner-clean and intentionally relies on runtime enforcement.
With the default no-network seccomp profile, creating the socket raises
PermissionError: [Errno 1] Operation not permitted.
"""

from __future__ import annotations

import socket


HOST = "127.0.0.1"
PORT = 9
TIMEOUT_SECONDS = 1


def main() -> None:
    print("attempting one outbound socket operation", flush=True)
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.settimeout(TIMEOUT_SECONDS)
    client.connect((HOST, PORT))
    client.close()


if __name__ == "__main__":
    main()
