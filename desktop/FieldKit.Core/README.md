# FieldKit desktop diagnostics core 1.0.0

This .NET 10 library has no runtime NuGet dependencies. All diagnostics are opt-in. The GUI consumes `Analyzer` asynchronous methods and `Report` observations without shell commands assembled from targets.

| Tool | What it measures | Limits |
| --- | --- | --- |
| Networks | Every OS network adapter, with independent IPv4/IPv6 prefixes, gateways and DNS servers | Gateway presence does not establish the default route. VPN classification combines OS type and recognizable adapter names. |
| LAN | ICMP reply, successful/refused TCP handshake, system reverse DNS, UPnP friendly names | IPv4 CIDR or one IPv4 address, at most 4,096 targets, at most 32 concurrent hosts. Default profile checks 18 conventional TCP ports on responding hosts and four reachability ports otherwise. Custom ports are checked on every target. No inferred Bluetooth state, invented names or IPv6-to-IPv4 device correlation. |
| Ports | Actual TCP connection status and time | At most 4,096 selected ports, 32 concurrent probes. If a hostname has multiple IPs, addresses are tried until one provides a conclusive response; the responding address is shown. Conventional service labels are hints, not detected software. |
| Ping | ICMP echo results | OS permissions and firewalls apply. Optional TCP fallback is explicitly labeled and does not count as ICMP latency. |
| DNS | System A/AAAA/PTR or direct custom-server A/AAAA/PTR/CNAME/MX/TXT/NS/SOA/SRV queries | Direct UDP replies validate transaction ID and question. Truncated UDP retries TCP within the same deadline. No DNSSEC validation. OS lookup provides no TTL. |
| Route | Windows `tracert` / Linux `traceroute` output | Linux needs the distribution's traceroute package. Missing replies do not establish a broken router. Targets are passed through `ProcessStartInfo.ArgumentList`, never a shell. |
| Wi-Fi | Windows `netsh wlan show interfaces`, or cached NetworkManager `nmcli` observations | Percentage signal is reported as supplied by the OS. No estimated distance, forced scan or made-up RSSI. Linux needs NetworkManager/nmcli; Windows privacy settings can restrict detail. |
| Registration | Read-only HTTPS RDAP, bootstrapped through rdap.org | Registry-published information does not identify an IP user's identity. HTTPS-only redirects, bounded JSON size and request deadline. |
| Wake-on-LAN | Sends a standard UDP magic packet | Sending confirms neither delivery nor that the device woke. Target firmware/OS must enable WOL. |

All tools follow the OS route and VPN policy. LAN and port scans optionally bind TCP to an explicit local source address. A failed bind is visible and never falls back to a different source. An explicitly bound LAN scan omits ICMP because the BCL ping API cannot bind its source.

UPnP discovery supplements responsive LAN devices with actual published friendly names. It sends a bounded SSDP M-SEARCH, accepts only responses inside the chosen range, and fetches at most 16 device descriptions. Description requests stay on the responding literal private/link-local/CGNAT/loopback IPv4 address, use no proxy or redirect, and cannot load XML DTDs/entities. Advertised services do not imply open TCP ports. The app does not correlate Bluetooth devices to arbitrary IP hosts.

`ReportStore` retains each tool's latest observation independently, including the original capture time, plus up to 500 archived observations and 200 favorites in the user's application-data directory. Writes use a temporary document, flush, and atomic replacement. Explicit history clearing preserves retained views and favorites. Corrupt saved documents are ignored; diagnostics do not restart automatically on restore. JSON export preserves exact data; CSV escapes cells and neutralizes leading spreadsheet formula markers.

## Build and verification

From the repository root with the pinned .NET 10 SDK:

```text
dotnet build desktop/FieldKit.Core/FieldKit.Core.csproj -c Release
dotnet run --project desktop/FieldKit.Core.Tests/FieldKit.Core.Tests.csproj -c Release
```

The console test runner has no test-framework packages. It exits nonzero on failure and performs network traffic only against loopback fixtures. It covers CIDR/port/target limits, source binding, real TCP handshake results, UDP DNS with TCP truncation fallback and malformed-reply rejection, SSDP plus HTTP friendly-name retrieval, actual WOL payloads, cancellation, and retained-report/favorite/export behavior. No LAN, public DNS or RDAP request is needed to run the tests.

Primary API/protocol references: [.NET adapters](https://learn.microsoft.com/en-us/dotnet/api/system.net.networkinformation.networkinterface.getallnetworkinterfaces), [.NET socket cancellation](https://learn.microsoft.com/en-us/dotnet/api/system.net.sockets.socket.connectasync), [process argument lists](https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.processstartinfo.argumentlist), [DNS RFC 1035](https://www.rfc-editor.org/rfc/rfc1035), [RDAP RFC 7482](https://www.rfc-editor.org/rfc/rfc7482).
