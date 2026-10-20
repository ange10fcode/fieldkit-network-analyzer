# FieldKit for iOS 1.0.0

Native SwiftUI application for iOS 16 and later, including iPad. It has no external package dependencies. The Xcode target compiles the same portable core that `Package.swift` tests independently.

## Build

Use Xcode 16 or later on macOS. Open `FieldKit.xcodeproj`, select the FieldKit scheme and a simulator, then Run. From the repository root:

```sh
swift test --package-path ios
xcodebuild -project ios/FieldKit.xcodeproj -scheme FieldKit \
  -sdk iphonesimulator -configuration Release \
  -destination 'generic/platform=iOS Simulator' \
  CODE_SIGNING_ALLOWED=NO build
```

After building with `-derivedDataPath work/ios-derived`, run a real Simulator launch smoke check:

```sh
python3 ios/smoke_simulator.py \
  --app work/ios-derived/Build/Products/Release-iphonesimulator/FieldKit.app \
  --output work/ios-smoke
```

The script lists available runtime names/versions, chooses the oldest installed supported iOS 16+ runtime with a compatible ordinary iPhone definition, creates a disposable simulator, boots it, installs and launches the built app, verifies the returned app process survives eight seconds, and captures `launch.png` plus `summary.json`. Choosing the oldest installed runtime exercises compatibility and avoids selecting an unnecessarily newer runtime than the active Xcode. It then terminates the app, shuts down and deletes only its own disposable simulator. All subprocess calls have bounded timeouts, including 600 seconds for first-boot completion and 60 seconds per cleanup call. It downloads no runtime and modifies no existing simulator. A failed install, launch, survival check, screenshot or cleanup exits unsuccessfully. This verifies startup only; it does not test radio hardware, ranging or every screen.

The committed project and opaque 1024 px app icon are deterministic. Regenerate them with `python3 ios/generate_project.py`; this uses only the Python standard library. The original icon is in `artwork/AppIcon.svg`. UI symbols use SF Symbols.

The repository's MIT license is included verbatim in the app bundle as `LICENSE.txt` and is available in Settings → App license.

For a physical iPhone, set a unique bundle identifier and your Apple developer team in Signing & Capabilities, then use Xcode Run or Product → Archive. A simulator `.app` cannot be installed on a physical iPhone. An installable signed IPA, TestFlight upload or App Store distribution needs an Apple developer account, certificates and provisioning. No Apple credentials or provisioning profiles are included.

## Included tools

- Separate IPv4/IPv6 interface inventory, including Wi-Fi, cellular and VPN/tunnel interfaces reported by `getifaddrs`. Interface classification is inferred from Apple interface names and labeled accordingly.
- Autodetected and manual IPv4 CIDR scans, limited to 4,096 addresses and 32 concurrent host jobs. Four initial TCP ports identify responsive hosts; then common ports are checked. A silent device may remain undiscovered.
- Bonjour names and advertised services for HTTP, HTTPS, SSH, printing, SMB, workstation, Google Cast and AirPlay audio. Published names and reverse DNS are shown as evidence. An ordinary device that publishes neither may remain unnamed.
- TCP port checks with configurable ports/ranges, at most 128 ports and 16 simultaneous checks.
- Saved TCP connection-time chart, explicitly distinguished from ICMP ping and Wi-Fi RSSI.
- Forward/reverse system DNS, human-readable public RDAP registration lookups and Wake-on-LAN magic packets.
- Bluetooth LE advertisements, actual RSSI history and a resettable baseline to compare stronger/weaker signal.
- Native precision finder using Apple Nearby Interaction, described below.
- Light, dark and system themes. Retained LAN, connection charts, Bluetooth observations and bounded history are stored atomically in the application container. Navigate back or close the app without losing them. Scans stop on background and never restart automatically. Cached data keeps its original timestamp.

Device tags are based on observed facts: IPv4, IPv6, this device, open TCP ports and Bonjour advertisements. IPv6 is listed separately rather than guessed to be the same physical device as an IPv4 host. Bluetooth identity and gateway role are not inferred from an IP address. Advertised ports are distinct from confirmed-open ports.

## Precision finder

1. Both iPhones run FieldKit and open Nearby → Precision finder. Runtime `NISession.deviceCapabilities` determines whether precise distance and direction are available. Unsupported phones see that status before pairing.
2. On one phone, choose **Make this phone discoverable**. Privately share its temporary 128-bit pairing code with the other person.
3. On the other phone, paste the code, choose **Find the other phone**, then select the temporary device name. The first phone explicitly approves the invitation.
4. Required-encryption Multipeer Connectivity carries a fresh challenge/HMAC proof, then securely archived Nearby Interaction discovery tokens. The secret is never advertised. Tokens are exchanged only after proof of the shared secret. Session state and secrets are cleared on stop or background.
5. Nearby Interaction supplies actual distance and optional direction. No RSSI-to-meter estimate or compass bearing is fabricated. Missing direction becomes distance-only; measurements older than three seconds display as stale. Hold the phone upright with its rear camera facing the search area; the arrow is relative to that facing direction.

This release ranges between compatible FieldKit iOS phones. It does not pair with AirTags, SmartTags or the Android app's UWB protocol, and does not use Apple's Find My network. Ranging requires foreground use on both phones. No background Nearby Interaction mode or camera assistance is requested.

## iOS limits and permissions

Local Network permission is needed for LAN discovery and peer pairing. Bluetooth permission is requested when starting BLE scanning; Nearby Interaction permission is requested for ranging. Denied permissions have explanatory status messages. Allow these in Settings if previously denied.

Apple provides no general-purpose iOS API for Wi-Fi neighbor scans. This app does not report that restriction as absent hardware. Wi-Fi channel surveys/RSSI monitoring, cellular signal strength, ARP inventory, raw packet capture and traceroute are not implemented on iOS. DNS follows system/VPN policy; selecting a TCP interface does not change system DNS routing. Default TCP routing respects iOS and VPN policy; selecting an interface is explicit and may be blocked by the VPN.

Wake-on-LAN sends a UDP packet and never claims the target woke. Broadcast/multicast may require Apple's restricted multicast entitlement; the default project does not claim that entitlement. Unicast wake destinations can work when the target/network permits it. Bonjour uses the supported system discovery API.

Apple documents the relevant restrictions and APIs:

- [iOS Wi-Fi API overview](https://developer.apple.com/documentation/technotes/tn3111-ios-wifi-api-overview)
- [Understanding local network privacy](https://developer.apple.com/documentation/technotes/tn3179-understanding-local-network-privacy)
- [Nearby Interaction](https://developer.apple.com/documentation/nearbyinteraction)
- [Runtime device capabilities](https://developer.apple.com/documentation/nearbyinteraction/nisession/devicecapabilities)
- [Peer-token exchange through Multipeer Connectivity](https://developer.apple.com/documentation/nearbyinteraction/discovering-peers-with-multipeer-connectivity)
- [Privacy required-reason APIs](https://developer.apple.com/documentation/bundleresources/app-privacy-configuration/nsprivacyaccessedapitypes/nsprivacyaccessedapitype)

## Validation and physical-device checks

Source/project structure and resources were prepared on Windows, where Xcode and Apple runtimes are unavailable. The repository CI runs the Swift package tests and simulator build on macOS. A green CI build is required before claiming compiler verification. A simulator does not verify Bluetooth radio behavior, real LAN permissions/routing or UWB ranging.

Before distribution, run on actual iPhones: permission allow/deny flows; Wi-Fi plus cellular plus VPN inventory; scan and Bonjour naming on a known network; Back/background/relaunch persistence; TCP tools against known open/closed ports; BLE baseline/history; unsupported precision finder; and private pairing/ranging on two compatible iPhones. Test wrong pairing codes, disconnects, background, stale measurements and distance-only operation. No physical iPhone or Apple signing account was available in the development workspace.
