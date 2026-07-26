import os
import time

children = []
for _ in range(64):
    pid = os.fork()
    if pid == 0:
        time.sleep(30)
        raise SystemExit(0)
    children.append(pid)

for pid in children:
    os.waitpid(pid, 0)
