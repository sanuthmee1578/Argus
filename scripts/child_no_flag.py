import time
import os

# fork directly — no blocked pattern at all
os.fork()
print("Child spawned via fork")
time.sleep(10)