# Changelog

## 1.0.0 — first public release

- Preserve the Android network analyzer and its separate Wi-Fi, cellular, VPN
  and Ethernet inventory, LAN discovery, device names/tags, diagnostics and themes.
- Add a shared Windows/Linux desktop application and a native iOS application.
- Keep actual observations and their ages across navigation and ordinary restarts.
- Gate precision finding on platform availability, hardware, permission and a
  compatible peer. No support for commercial AirTag/SmartTag tracking networks
  is implied.
- Add public build workflows, dependency locks, third-party notices, release
  checksums and platform-specific build/signing documentation.

The earlier Android 1.x builds were private prototypes. Public semantic versioning
starts at 1.0.0; Android's internal version code remains higher than those builds
so an update signed with the same key can preserve installed data.
