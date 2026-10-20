FieldKit 1.0 introduces public Android, Windows, Linux and iOS source releases with separate interface inventory, suggested targets, retained results and themes.

- **Android:** signed APK for Android 8.0+. LAN discovery, names/observed tags, TCP ports, diagnostics, Wi-Fi/Bluetooth, optional Wi-Fi RTT and hardware-gated UWB peer finding.
- **Windows/Linux:** portable self-contained x64 apps with LAN discovery, services, ports, ping, DNS, traceroute, RDAP, Wake-on-LAN and saved reports. No separate .NET installation needed. Windows executables are not Authenticode signed.
- **iOS:** native SwiftUI app for iOS 16+ with LAN/Bonjour, TCP tools, DNS/RDAP, BLE and capability-gated Nearby Interaction. Simulator and unsigned archive downloads need Apple signing for phone installation; no signed IPA is included.

VPN routing and OS permissions still apply. Names depend on published DNS/services. Retained observations have timestamps and do not imply background scanning.

Precision finding requires compatible hardware and cooperating peers. Android and iOS protocols are separate. AirTag, SmartTag, Find My and Google tracking-network integration are not included. Physical radio/ranging checks remain required.

**Private Android prototype users:** export wanted results, then uninstall the prototype before installing 1.0. The public release uses a new private signing key; future official updates retain it.

See the README platform matrix and build instructions. Download `SHA256SUMS.txt` to verify packages. Source is MIT licensed with dependency notices included.
