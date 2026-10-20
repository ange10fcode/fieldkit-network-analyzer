# FieldKit desktop 1.0

A native Windows and Linux network toolkit built with .NET 10 LTS and Avalonia 11.3.22. It includes independent network interface inventory, LAN discovery and names where published, TCP port scans, ping, DNS, traceroute, RDAP and Wake-on-LAN. System, light and dark themes are available in Settings. Results and form entries are retained locally between launches.

## Run

- **Windows x64:** extract the entire ZIP and open `FieldKit.exe`. Windows 10 22H2 or Windows 11. The portable build is unsigned; no administrator access is required for ordinary tools.
- **Linux x64:** extract the archive, run `chmod +x FieldKit` if needed, then `./FieldKit`. Use a graphical desktop with X11 or XWayland. Native rendering needs common desktop libraries including X11, fontconfig and OpenGL/Mesa. On Ubuntu: `sudo apt-get install libx11-6 libice6 libsm6 libfontconfig1 libgl1`. Traceroute needs your distribution's `traceroute` package. Optional Wi-Fi information uses NetworkManager's `nmcli`.
- No separate .NET installation is needed for self-contained release packages. Keep the bundled libraries and `licenses/` directory beside the executable.

LAN discovery uses IPv4 ranges of at most 4,096 targets. Other tools accept IPv4/IPv6 where supported. A responding probe establishes reachability; a device that ignores probes may be absent. Names depend on local DNS or device advertisements. OS routing and VPN policies apply. The UI does not bypass a VPN.

Wi-Fi signal is an observed snapshot where the OS exposes it. Desktop 1.0 does not implement Bluetooth discovery, Wi-Fi RTT ranging or UWB pairing. It never derives a bearing or distance from IP addresses or signal strength. The Android version has additional radio features; platform support is described in the repository's capability table.

## Build

Install the official .NET SDK pinned by `global.json`, then from this directory:

```sh
dotnet restore FieldKit.Desktop/FieldKit.Desktop.csproj --locked-mode
dotnet build FieldKit.Desktop/FieldKit.Desktop.csproj -c Release --no-restore
dotnet run --project FieldKit.Core.Tests -c Release
dotnet publish FieldKit.Desktop/FieldKit.Desktop.csproj -c Release -r win-x64 --self-contained true -o publish/win-x64
dotnet publish FieldKit.Desktop/FieldKit.Desktop.csproj -c Release -r linux-x64 --self-contained true -o publish/linux-x64
```

Dependency versions and content hashes are committed in `FieldKit.Desktop/packages.lock.json`. Avalonia's optional BuildServices assets are excluded, including its build-time telemetry task. There is no app telemetry or account service. The public RDAP lookup contacts registration services; diagnostic tools contact the requested target/resolver. Full dependency notices are bundled under `licenses/`.

## Runtime checks

`FieldKit --smoke-test` performs read-only interface inventory and a temporary report-storage round trip, without sending network probes. `FieldKit --smoke-ui --data-dir /tmp/fieldkit-ui-check --screenshot preview.png` opens the real window, initializes every tool view, renders only that window to an optional PNG, and closes automatically. `--smoke-view lan` selects the final view to capture. A graphical session is needed; Linux CI can use `xvfb-run`. Both return a nonzero exit code on failure. `--version` prints the release version.

Normal settings and result storage use `Environment.SpecialFolder.LocalApplicationData/FieldKit` (shown in Settings). Use `--data-dir PATH` to choose a separate directory, including for portable installations or QA. No scans resume automatically after reopening; saved observations retain their original timestamp.

The screenshots under `screenshots/` show an explicitly labeled loopback preview fixture, with no private network details. They demonstrate the light/dark layout and saved-result presentation; they are not evidence of a device discovery run.
