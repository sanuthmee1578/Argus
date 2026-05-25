import subprocess
import time

subprocess.Popen(["sleep", "30"])
print("spawned child")
time.sleep(30)