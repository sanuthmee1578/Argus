import subprocess
import time

subprocess.Popen(["bash", "-c", "sleep 5"])
print("Suspicious child spawned")
time.sleep(10)