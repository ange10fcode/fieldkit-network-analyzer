# Validation and device checks

Compiler, automated-test and physical-device checks prove different things. Successful builds do not establish radio availability, VPN policy or peer ranging.

## Automated checks

- Android: 2,594 parser, retained-model and actual loopback assertions through `scripts/test_android.py`; complete APK build; signed-package signature/alignment checks.
- Desktop: 88 loopback, input, DNS wire-format and persistence checks. UI smoke mode opens the application and initializes eleven tool views. Windows and Linux run separately in CI.
- iOS: portable Swift core tests, Simulator compilation and unsigned device archive on macOS CI.
- Public source: version, dependency pinning and private-material checks through `scripts/verify_release.py`.

Actions results record verification for each commit. Local Windows checks covered desktop startup/persistence and Android packaging. Earlier API 26/API 34 emulator checks covered Android navigation, retained results and unsupported optional-radio paths. No physical iPhone or two-peer UWB setup was available during preparation.

## Real-device checklist

1. Wi-Fi, cellular and VPN interfaces visible together; explicit source selection either works or reports its restriction.
2. Manual LAN ranges, responsive/silent devices, published names, observed tags and custom TCP ports.
3. Permission allow/deny, Back/background/relaunch, timestamps, clear/export controls.
4. BLE advertisements, stale readings and stronger/weaker history without invented meters or identity joins.
5. Unsupported precision finder; permission/service errors on supported hardware.
6. Two compatible Android FieldKit phones for UWB; separately, two compatible iPhones for Nearby Interaction. Check incorrect codes, disconnects, background, stale data and distance-only readings.
7. Wi-Fi RTT with a compatible responding Android/access-point pair; RTT supplies no bearing.

The Galaxy S10e can use general Android tools and BLE observations; UWB precision finding is unavailable on that model. iOS general Wi-Fi surveys/cellular RSSI and desktop BLE/UWB are unavailable in this release and labeled accordingly.
