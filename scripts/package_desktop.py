#!/usr/bin/env python3
"""Package only a completed self-contained publish directory."""
import argparse
from pathlib import Path
import tarfile
import zipfile

parser = argparse.ArgumentParser()
parser.add_argument("rid", choices=("win-x64", "linux-x64"))
parser.add_argument("publish", type=Path)
parser.add_argument("output", type=Path)
args = parser.parse_args()
publish = args.publish.resolve()
args.output.mkdir(parents=True, exist_ok=True)
executable = publish / ("FieldKit.exe" if args.rid == "win-x64" else "FieldKit")
if not executable.is_file():
    raise SystemExit("Publish directory is missing its application executable")
files = sorted(p for p in publish.rglob("*") if p.is_file())
if args.rid == "win-x64":
    artifact = args.output / "FieldKit-1.0.0-Windows-x64.zip"
    with zipfile.ZipFile(artifact, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for file in files:
            archive.write(file, "FieldKit/" + file.relative_to(publish).as_posix())
else:
    artifact = args.output / "FieldKit-1.0.0-Linux-x64.tar.gz"
    with tarfile.open(artifact, "w:gz") as archive:
        for file in files:
            entry = archive.gettarinfo(str(file), "FieldKit/" + file.relative_to(publish).as_posix())
            entry.uid = entry.gid = 0
            entry.uname = entry.gname = ""
            entry.mode = 0o755 if file == executable or file.suffix == ".sh" else 0o644
            with file.open("rb") as data:
                archive.addfile(entry, data)
print(artifact)
