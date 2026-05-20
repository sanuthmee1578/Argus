import time

data = []
for i in range(50):
    data.append("A" * 1024 * 1024)  # adds about 1MB each loop
    time.sleep(0.1)

print("Memory test completed")