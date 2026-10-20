#!/usr/bin/env python3
"""Run the Android-independent network/parser regressions on any JDK host."""
from __future__ import annotations
import hashlib
import os
from pathlib import Path
import subprocess
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / "work" / "android-tests"
JSON_URL = "https://repo.maven.apache.org/maven2/org/json/json/20250517/json-20250517.jar"
JSON_SHA256 = "3ea61b2a06e31edf1c91134fe9106b0ebb16628be169f3db75bc7a2b06b45796"
SOURCES = ("Ip DnsClient NetworkTools Report Task LanSelection NetworkInventoryLogic "
           "LanServiceMerge NearbySignal NearbySnapshot SnapshotDocument DeviceFacts "
           "LanNameDiscovery SsdpNames UwbPairing PrecisionReading").split()

def main() -> None:
    WORK.mkdir(parents=True, exist_ok=True)
    jar = WORK / "json-20250517.jar"
    if not jar.exists():
        with urllib.request.urlopen(JSON_URL, timeout=60) as response:
            jar.write_bytes(response.read())
    if hashlib.sha256(jar.read_bytes()).hexdigest() != JSON_SHA256:
        raise SystemExit("JSON test dependency failed SHA-256 verification")
    output = WORK / "classes"
    output.mkdir(exist_ok=True)
    source = ROOT / "android/app/src/main/java/com/fieldkit/analyzer"
    tests = sorted((ROOT / "android/tests").glob("*.java"))
    files = [source / (name + ".java") for name in SOURCES] + tests
    arguments = WORK / "sources.txt"
    arguments.write_text("\n".join('"' + f.as_posix() + '"' for f in files), encoding="utf-8")
    subprocess.run(["javac", "--release", "8", "-encoding", "UTF-8", "-cp", str(jar),
                    "-d", str(output), "@" + str(arguments)], check=True)
    for test in tests:
        subprocess.run(["java", "-cp", str(jar) + os.pathsep + str(output),
                        "com.fieldkit.analyzer." + test.stem], check=True)

if __name__ == "__main__":
    main()
