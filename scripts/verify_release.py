#!/usr/bin/env python3
"""Check public source metadata and reject accidentally bundled private material."""
from pathlib import Path
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
VERSION = "1.0.0"
errors = []

def require(condition: bool, message: str) -> None:
    if not condition:
        errors.append(message)

require((ROOT / "VERSION").read_text().strip() == VERSION, "VERSION differs from 1.0.0")
require((ROOT / "LICENSE").read_text().startswith("MIT License"), "MIT license missing")
manifest = ET.parse(ROOT / "android/app/src/main/AndroidManifest.xml").getroot()
ns = "{http://schemas.android.com/apk/res/android}"
require(manifest.get(ns + "versionName") == VERSION, "Android public version mismatch")
require(int(manifest.get(ns + "versionCode", "0")) >= 7, "Android update code must exceed prototypes")
gradle = (ROOT / "android/app/build.gradle").read_text()
require("versionName '1.0.0'" in gradle, "Gradle public version mismatch")
require("System.getenv('FIELDKIT_KEYSTORE_PATH')" in gradle, "Private signing must come from environment")
require("storePassword 'android'" not in gradle, "Prototype signing password in release configuration")
wrapper = (ROOT / "android/gradle/wrapper/gradle-wrapper.properties").read_text()
require("distributionSha256Sum=f397b287023acdba1e9f6fc5ea72d22dd63669d59ed4a289a29b1a76eee151c6" in wrapper,
        "Pinned Gradle distribution checksum missing")
for required in ("README.md", "PRIVACY.md", "SECURITY.md", "docs/BUILDING.md", "docs/RELEASING.md",
                 ".github/workflows/ci.yml", ".github/workflows/release.yml",
                 "desktop/FieldKit.Desktop/FieldKit.Desktop.csproj", "ios/FieldKit.xcodeproj/project.pbxproj"):
    require((ROOT / required).is_file(), "Missing " + required)

# Use the tracked list when possible, so generated local build products are not source.
git = subprocess.run(["git", "-C", str(ROOT), "ls-files", "-z"], capture_output=True)
if git.returncode == 0 and git.stdout:
    files = [ROOT / p for p in git.stdout.decode().split("\0") if p]
else:
    ignored = {".git", ".gradle", "build", "bin", "obj", "work", ".build", "DerivedData", "artifacts"}
    files = [p for p in ROOT.rglob("*") if p.is_file() and not any(part in ignored for part in p.relative_to(ROOT).parts)]
for file in files:
    relative = file.relative_to(ROOT)
    require(file.suffix.lower() not in {".jks", ".keystore", ".p12", ".pfx", ".mobileprovision", ".pem", ".key"},
            "Private signing material: " + str(relative))
    require(not any(part in {".gradle", "bin", "obj", "DerivedData", "signing-private"} for part in relative.parts),
            "Generated/private path tracked: " + str(relative))
    if file.suffix.lower() in {".java", ".swift", ".cs", ".md", ".json", ".yml", ".yaml", ".gradle", ".ps1", ".sh", ".txt"}:
        text = file.read_text(encoding="utf-8", errors="replace")
        require(not re.search(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", text),
                "Private key content in " + str(relative))
        require(not re.search(r"(?:ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})", text),
                "Possible GitHub token in " + str(relative))
if errors:
    print("Release source check failed:\n" + "\n".join("- " + error for error in errors))
    sys.exit(1)
print(f"Public release source check passed ({len(files)} source files; no signing keys)")
