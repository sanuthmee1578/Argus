import subprocess
import time

# This spawns bash which spawns sleep in background, making bash wait
# So we can catch bash as a child process instead of it exiting immediately
subprocess.Popen(["bash", "-c", "sleep 5 & wait"])
print("Suspicious child spawned")
time.sleep(10)