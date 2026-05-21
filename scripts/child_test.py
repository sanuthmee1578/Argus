import subprocess
import time

subprocess.Popen(["sleep", "5"])

print("Child process spawned")

time.sleep(10)