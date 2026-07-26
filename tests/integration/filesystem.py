from pathlib import Path

print(Path("/etc/passwd").read_text().splitlines()[0])
Path("/tmp/argus-filesystem-test.txt").write_text("argus filesystem fixture\n")
