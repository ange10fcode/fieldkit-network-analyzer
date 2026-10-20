#!/usr/bin/env python3
"""Generate SHA256SUMS for completed release artifacts, without self-hashing."""
import argparse
import hashlib
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("directory", type=Path)
args = parser.parse_args()
directory = args.directory.resolve()
files = sorted(p for p in directory.iterdir() if p.is_file() and p.name != "SHA256SUMS.txt")
lines = []
for artifact in files:
    digest = hashlib.sha256()
    with artifact.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    lines.append(f"{digest.hexdigest()}  {artifact.name}")
(directory / "SHA256SUMS.txt").write_text("\n".join(lines) + "\n", encoding="ascii")
print(f"Wrote checksums for {len(lines)} artifacts")
