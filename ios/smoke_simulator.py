#!/usr/bin/env python3
"""Install and launch the real app on a disposable, already-installed iOS runtime.

Requires macOS and Xcode. This checks launch/process survival, not radio features or
screen interaction. Every subprocess has a timeout. No runtime is downloaded and
no existing simulator is erased, shut down or modified.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import plistlib
import re
import subprocess
import sys
import time
import uuid


class SmokeError(RuntimeError):
    pass


def command(arguments: list[str], timeout: int = 45) -> str:
    try:
        result = subprocess.run(arguments, text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as error:
        raise SmokeError(f"Command timed out after {timeout}s: {arguments!r}") from error
    except OSError as error:
        raise SmokeError(f"Cannot execute {arguments[0]}: {error}") from error
    if result.returncode:
        raise SmokeError(f"Command failed ({result.returncode}): {arguments!r}\n"
                         f"{result.stdout[-5000:]}\n{result.stderr[-5000:]}")
    return result.stdout.strip()


def simctl(*arguments: str, timeout: int = 45) -> str:
    return command(["xcrun", "simctl", *arguments], timeout=timeout)


def select_runtime(inventory: dict) -> tuple[dict, dict]:
    """Exercise compatibility on the oldest installed supported runtime.

    Newer simulator runtimes may appear available even when an older selected
    Xcode cannot reliably boot them. Prefer an ordinary iPhone definition on the
    oldest available iOS16+ runtime rather than choosing the highest OS number.
    """
    candidates = []
    for runtime in inventory.get("runtimes", []):
        identifier = runtime.get("identifier", "")
        if ".iOS-" not in identifier or not runtime.get("isAvailable", False):
            continue
        version = tuple(int(part) for part in re.findall(r"\d+", runtime.get("version", "")))
        if not version or version[0] < 16:
            continue
        for device in inventory.get("devices", {}).get(identifier, []):
            if not device.get("isAvailable", False) or not device.get("name", "").startswith("iPhone"):
                continue
            if not device.get("deviceTypeIdentifier"):
                continue
            candidates.append((version, device.get("name", ""), runtime, device))
    if not candidates:
        raise SmokeError("No installed available iOS 16+ iPhone Simulator definition found. "
                         "Install an iOS runtime in Xcode and create an iPhone simulator first.")
    _, _, runtime, device = min(candidates, key=lambda item: (
        item[0], 0 if re.fullmatch(r"iPhone \d+", item[1]) else 1, item[1]))
    return runtime, device


def verify_process(pid: int, executable: str) -> str:
    try:
        os.kill(pid, 0)
    except OSError as error:
        raise SmokeError(f"Launched app process {pid} exited or is inaccessible: {error}") from error
    process = command(["/bin/ps", "-p", str(pid), "-o", "comm="], timeout=5)
    # PID comes directly from simctl launch; confirm its executable as well as existence.
    if Path(process).name != executable:
        raise SmokeError(f"PID {pid} no longer belongs to {executable!r}: {process!r}")
    return process


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", required=True, type=Path, help="Built Simulator .app directory")
    parser.add_argument("--output", type=Path, default=Path("work/ios-smoke"))
    parser.add_argument("--observe-seconds", type=int, default=8, choices=range(2, 31), metavar="2..30")
    args = parser.parse_args()
    if sys.platform != "darwin":
        parser.error("This smoke test requires macOS with Xcode and an installed iOS Simulator runtime.")
    app = args.app.resolve()
    if not app.is_dir() or app.suffix != ".app":
        parser.error("--app must point to a built Simulator .app directory.")
    try:
        with (app / "Info.plist").open("rb") as stream:
            info = plistlib.load(stream)
    except (OSError, plistlib.InvalidFileException) as error:
        parser.error(f"Cannot read built app Info.plist: {error}")
    bundle = info.get("CFBundleIdentifier", "")
    executable = info.get("CFBundleExecutable", "")
    if not re.fullmatch(r"[A-Za-z0-9.-]+", bundle) or not executable or "$" in executable:
        parser.error("Built app has no resolved bundle identifier/executable.")
    if info.get("CFBundleSupportedPlatforms") != ["iPhoneSimulator"]:
        parser.error("Use a Simulator build; a physical-device .app cannot run here.")
    args.output.mkdir(parents=True, exist_ok=True)
    summary = {"bundle": bundle, "scope": "Simulator install, launch, process survival and screenshot only",
               "status": "failed", "radio_tests": "not performed"}
    device_id = None
    launched = False
    failure = None
    cleanup_errors = []
    try:
        inventory = json.loads(simctl("list", "--json"))
        runtime_names = [f"{item.get('name', 'iOS')} ({item.get('version', '?')})"
                         for item in inventory.get("runtimes", [])
                         if ".iOS-" in item.get("identifier", "") and item.get("isAvailable", False)]
        print("Available iOS runtimes: " + ", ".join(runtime_names), flush=True)
        runtime, template = select_runtime(inventory)
        summary.update(runtime=runtime.get("name", runtime["identifier"]), device=template["name"])
        # A fresh disposable simulator avoids changing or deleting any existing app/data.
        device_id = simctl("create", "FieldKitSmoke-" + uuid.uuid4().hex[:8],
                           template["deviceTypeIdentifier"], runtime["identifier"], timeout=60)
        if not re.fullmatch(r"[0-9A-Fa-f-]{36}", device_id):
            raise SmokeError(f"Unexpected simulator identifier returned: {device_id!r}")
        summary["simulator_udid"] = device_id
        print(f"Booting disposable {summary['device']} · {summary['runtime']}", flush=True)
        simctl("boot", device_id, timeout=90)
        print("Waiting for simulator OS boot to complete (deadline 600s)…", flush=True)
        simctl("bootstatus", device_id, "-b", timeout=600)
        print("Simulator booted. Installing the built FieldKit app…", flush=True)
        simctl("install", device_id, str(app), timeout=90)
        print("Launching FieldKit…", flush=True)
        launch_output = simctl("launch", device_id, bundle, timeout=60)
        summary["launch_output"] = launch_output
        launched = True
        match = re.search(r"(?m)^" + re.escape(bundle) + r":\s*(\d+)\s*$", launch_output)
        if not match:
            raise SmokeError(f"App launch returned no process identifier: {launch_output!r}")
        pid = int(match.group(1))
        summary["pid"] = pid
        start = time.monotonic()
        checks = 0
        while True:
            summary["process"] = verify_process(pid, executable)
            checks += 1
            elapsed = time.monotonic() - start
            if elapsed >= args.observe_seconds:
                break
            time.sleep(min(1, args.observe_seconds - elapsed))
        summary.update(process_checks=checks, observed_seconds=round(time.monotonic() - start, 2))
        screenshot = args.output.resolve() / "launch.png"
        simctl("io", device_id, "screenshot", str(screenshot), timeout=30)
        if not screenshot.is_file() or screenshot.stat().st_size == 0:
            raise SmokeError("Simulator screenshot was not produced.")
        summary.update(status="passed", screenshot=str(screenshot))
        print(f"Installed and launched {bundle}; PID {pid} survived {summary['observed_seconds']}s. "
              "Radio features and screen interaction were not tested.", flush=True)
    except (SmokeError, ValueError, KeyError, OSError) as error:
        failure = str(error)
        summary["error"] = failure
    finally:
        # Only the simulator created by this invocation is ever terminated/shut down/deleted.
        if device_id and re.fullmatch(r"[0-9A-Fa-f-]{36}", device_id):
            operations = []
            if launched:
                operations.append(("terminate", device_id, bundle))
            operations.extend([("shutdown", device_id), ("delete", device_id)])
            for operation in operations:
                try:
                    print(f"Cleaning up disposable simulator: {operation[0]}", flush=True)
                    simctl(*operation, timeout=60)
                except SmokeError as error:
                    cleanup_errors.append(str(error))
        summary["cleanup"] = "passed" if not cleanup_errors else cleanup_errors
        if cleanup_errors:
            summary["status"] = "failed"
        (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    if failure:
        print(f"Simulator smoke test failed: {failure}", file=sys.stderr)
    for error in cleanup_errors:
        print(f"Simulator cleanup failed: {error}", file=sys.stderr)
    return 1 if failure or cleanup_errors else 0


if __name__ == "__main__":
    sys.exit(main())
