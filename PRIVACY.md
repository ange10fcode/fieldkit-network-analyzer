# Privacy

FieldKit stores retained results, history, device labels and preferences on the
device. The application has no FieldKit account or cloud inventory service and
does not automatically upload reports. Exporting or sharing a report sends it
only to the destination chosen through the operating system.

Network operations happen when a tool is started. Targets receive the probes;
DNS resolvers receive DNS questions; RDAP registries receive registration queries;
and an explicitly selected speed-test endpoint receives transfer traffic. Local
Bonjour, SSDP and Wake-on-LAN discovery use local networking. OS-managed network
APIs can have additional platform behavior outside the application's control.

On Android, optional UWB support uses AndroidX and the phone's Google/OEM ranging
service. On iOS, nearby ranging and peer discovery use Apple's platform APIs.
Precision pairing is limited to compatible peers and is not access to a public
device-tracking network. Do not publish private pairing codes or session tokens.

Saved results are observations with a timestamp, not background monitoring.
Leaving an active foreground tool stops its work. Clear the relevant retained
views and history when removing stored results; uninstalling/removing app data
also deletes local data. Exported copies are managed by their destination.

Permission prompts describe local network, location, Bluetooth and nearby-device
uses where applicable. A permission or hardware restriction is displayed rather
than replaced with invented values. Full Wi-Fi surveys and target direction are
not available on every platform or device.
