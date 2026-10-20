import SwiftUI
import Charts
import MultipeerConnectivity

struct ContentView: View {
    @EnvironmentObject private var model: AppModel
    var body: some View {
        TabView(selection: $model.selectedTab) {
            NavigationStack { NetworksView() }.tabItem { Label("Networks", systemImage: "network") }.tag(0)
            NavigationStack { LANView() }.tabItem { Label("LAN", systemImage: "desktopcomputer") }.tag(1)
            NavigationStack { ToolsView() }.tabItem { Label("Tools", systemImage: "wrench.and.screwdriver") }.tag(2)
            NavigationStack { NearbyView() }.tabItem { Label("Nearby", systemImage: "dot.radiowaves.left.and.right") }.tag(3)
            NavigationStack { SettingsView() }.tabItem { Label("Settings", systemImage: "gearshape") }.tag(4)
        }
        .alert("FieldKit", isPresented: Binding(get: { model.error != nil }, set: { if !$0 { model.error = nil } })) { Button("OK") { model.error = nil } } message: { Text(model.error ?? "") }
    }
}

private struct NetworksView: View {
    @EnvironmentObject private var model: AppModel
    var body: some View {
        List {
            Section {
                Label(model.pathStatus, systemImage: model.pathStatus.hasPrefix("Connected") ? "checkmark.circle.fill" : "exclamationmark.circle")
                    .foregroundStyle(model.pathStatus.hasPrefix("Connected") ? .teal : .secondary)
            } footer: { Text("Each interface retains its own IPv4 and IPv6 addresses. A VPN does not replace the other entries. Addresses are observed interfaces; routing still follows iOS policy.") }
            ForEach(Array(Set(model.addresses.map(\.interface))).sorted(), id: \.self) { name in
                let entries = model.addresses.filter { $0.interface == name }
                Section("\(entries.first?.kind ?? "Interface") · \(name)") {
                    ForEach(entries) { entry in
                        VStack(alignment: .leading, spacing: 6) {
                            Text(entry.address).font(.system(.body, design: .monospaced)).textSelection(.enabled)
                            HStack {
                                TagPill(text: entry.isIPv6 ? "IPv6" : "IPv4")
                                Text("Prefix /\(entry.prefix)").font(.caption).foregroundStyle(.secondary)
                                Spacer()
                                if let subnet = entry.subnet {
                                    Button("Scan LAN") { model.saved.subnet = subnet; model.selectedTab = 1; model.persist() }.font(.caption.weight(.semibold))
                                }
                            }
                        }.padding(.vertical, 3)
                    }
                }
            }
            if model.addresses.isEmpty { Section { Text("No active IP interfaces found. Connect to Wi-Fi or cellular, then refresh.").foregroundStyle(.secondary) } }
            Section("Platform capabilities") {
                Label("LAN tools and Bluetooth LE signal finding", systemImage: "checkmark.circle").foregroundStyle(.teal)
                Label("Wi-Fi neighbor scans and RSSI surveys are restricted by iOS", systemImage: "info.circle").foregroundStyle(.secondary)
                Text("Use Nearby for supported precision ranging. Ordinary LAN devices cannot be located by a compass from their IP address.").font(.footnote).foregroundStyle(.secondary)
            }
        }
        .navigationTitle("Your networks")
        .toolbar { Button { model.refresh() } label: { Label("Refresh", systemImage: "arrow.clockwise") } }
        .refreshable { model.refresh() }
    }
}

private struct RoutePicker: View {
    @EnvironmentObject private var model: AppModel
    var body: some View {
        Picker("Route", selection: $model.saved.route) {
            Text("System / VPN policy").tag("")
            ForEach(model.routeNames, id: \.self) { Text($0).tag($0) }
            if !model.saved.route.isEmpty && !model.routeNames.contains(model.saved.route) { Text("\(model.saved.route) · unavailable").tag(model.saved.route) }
        }
    }
}

private struct LANView: View {
    @EnvironmentObject private var model: AppModel
    @State private var device: LANDevice?
    @State private var showLegend = false
    var body: some View {
        List {
            Section {
                HStack {
                    TextField("192.168.1.0/24", text: $model.saved.subnet).keyboardType(.numbersAndPunctuation).textInputAutocapitalization(.never).autocorrectionDisabled()
                    Menu { ForEach(model.suggestedSubnets, id: \.self) { value in Button(value) { model.saved.subnet = value } } } label: { Image(systemName: "chevron.down.circle") }.accessibilityLabel("Connected subnet suggestions")
                }
                DisclosureGroup("Routing") { RoutePicker(); Text(model.routeDescription).font(.caption).foregroundStyle(.secondary) }
                Button { model.running ? model.stop() : model.scanLAN() } label: {
                    HStack { Image(systemName: model.running ? "stop.circle.fill" : "play.circle.fill"); Text(model.running ? "Stop scan" : "Discover devices").fontWeight(.semibold); Spacer(); if model.running { ProgressView() } }
                }
            } footer: { Text("Up to 4,096 IPv4 addresses. TCP probes use 22, 80, 443 and 445; responding devices receive a common-port check. Bonjour adds published local services, including IPv6, through system discovery independently of the TCP interface selection.") }
            Section {
                if let date = model.saved.lanDate {
                    HStack { Text("\(model.saved.devices.count) devices").fontWeight(.semibold); Spacer(); Text(date, style: .relative).foregroundStyle(.secondary); Text("ago").foregroundStyle(.secondary) }.font(.caption)
                }
                if !model.progress.isEmpty { Text(model.progress).font(.caption).foregroundStyle(.secondary) }
                if model.saved.devices.isEmpty {
                    VStack(alignment: .leading, spacing: 8) {
                        Label("Your device list stays here", systemImage: "tray.and.arrow.down") .font(.headline)
                        Text("Choose a connected subnet and start discovery. Results remain when you go back or reopen FieldKit.").font(.subheadline).foregroundStyle(.secondary)
                    }.padding(.vertical, 12)
                }
                ForEach(model.saved.devices) { value in
                    Button { device = value } label: { DeviceRow(device: value) }.buttonStyle(.plain)
                }
            }
            Section {
                DisclosureGroup("Color legend & discovery limits", isExpanded: $showLegend) {
                    ForEach(["IPv4", "IPv6", "This device", "TCP open", "Bonjour"], id: \.self) { tag in
                        HStack { TagPill(text: tag); Text(legend(tag)).font(.caption).foregroundStyle(.secondary) }
                    }
                    Text("Bluetooth, gateway role and vendor are unknown unless independently verified. iOS does not expose an ARP table or a dependable gateway API to this app. An advertised service is not confirmation that its TCP port accepts connections.").font(.caption).foregroundStyle(.secondary)
                }
            }
        }
        .navigationTitle("LAN devices")
        .toolbar { ShareLink(item: model.lanText) { Label("Export results", systemImage: "square.and.arrow.up") } }
        .sheet(item: $device) { value in NavigationStack { DeviceDetail(device: value) } }
        .onDisappear { model.persist() }
    }
    private func legend(_ tag: String) -> String {
        ["IPv4":"Observed IPv4 address", "IPv6":"Observed IPv6 address; listed independently", "This device":"Matches a current local interface", "TCP open":"At least one TCP handshake succeeded", "Bonjour":"Device published a local service"][tag] ?? ""
    }
}

private struct DeviceRow: View {
    let device: LANDevice
    var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            HStack { Text(device.displayName).font(.headline).lineLimit(2); Spacer(); Image(systemName: "chevron.right").font(.caption).foregroundStyle(.tertiary) }
            Text(device.address).font(.system(.subheadline, design: .monospaced)).foregroundStyle(.secondary).lineLimit(2)
            TagLayout { ForEach(device.tags, id: \.self) { TagPill(text: $0) } }
            if !device.openPorts.isEmpty { Text(device.openPorts.prefix(5).map { "\($0) \(PortSpec.service($0))" }.joined(separator: " · ")).font(.caption).foregroundStyle(.secondary).lineLimit(2) }
        }.padding(.vertical, 5)
    }
}

private struct DeviceDetail: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    let device: LANDevice
    var body: some View {
        Form {
            Section { Text(device.address).font(.system(.body, design: .monospaced)).textSelection(.enabled); Text("Observed \(device.observedAt.formatted())").font(.caption).foregroundStyle(.secondary) }
            Section("Identity") { LabeledContent("Name", value: device.displayName); LabeledContent("Source", value: device.nameSource.isEmpty ? "No published name found" : device.nameSource); LabeledContent("Bluetooth", value: "Unknown; not linked to an IP address"); LabeledContent("Gateway", value: "Unknown") }
            Section("Confirmed open TCP ports") {
                if device.openPorts.isEmpty { Text("No open TCP port confirmed.").foregroundStyle(.secondary) }
                ForEach(device.openPorts, id: \.self) { port in LabeledContent(String(port), value: PortSpec.service(port)) }
            }
            Section("Advertised services") {
                if device.advertisedServices.isEmpty { Text("None observed.").foregroundStyle(.secondary) }
                ForEach(device.advertisedServices, id: \.self) { Text($0) }
            }
            Section { Button("Use in tools") { model.saved.target = device.address; model.selectedTab = 2; model.persist(); dismiss() } }
        }.navigationTitle(device.displayName).navigationBarTitleDisplayMode(.inline).toolbar { Button("Done") { dismiss() } }
    }
}

private struct ToolsView: View {
    @EnvironmentObject private var model: AppModel
    @State private var mode = "Ports"
    @State private var mac = ""
    @State private var broadcast = "255.255.255.255"
    var body: some View {
        List {
            Section {
                Picker("Tool", selection: $mode) { ForEach(["Ports", "TCP monitor", "DNS", "Registration", "Wake on LAN"], id: \.self) { Text($0) } }
                if mode != "Wake on LAN" {
                    HStack {
                        TextField("IP address or hostname", text: $model.saved.target).textInputAutocapitalization(.never).autocorrectionDisabled().keyboardType(.URL)
                        Menu { ForEach(model.suggestedHosts, id: \.self) { target in Button(target) { model.saved.target = target } } } label: { Image(systemName: "chevron.down.circle") }.accessibilityLabel("Suggested targets")
                    }
                }
                if mode == "Ports" || mode == "TCP monitor" {
                    TextField("Ports: 22,80,443", text: $model.saved.ports).keyboardType(.numbersAndPunctuation)
                    RoutePicker()
                }
                if mode == "Wake on LAN" {
                    TextField("MAC address", text: $mac).textInputAutocapitalization(.characters).autocorrectionDisabled()
                    TextField("Directed broadcast or target IPv4", text: $broadcast).keyboardType(.numbersAndPunctuation)
                }
                toolActions
            } footer: {
                if mode == "TCP monitor" { Text("Measures TCP connection time to the first configured port. This is not ICMP ping or Wi-Fi RSSI. A blocked or closed port produces a gap, not a latency measurement.") }
                else if mode == "Registration" { Text("Sends this target to rdap.org and the authoritative public registration service over HTTPS.") }
                else if mode == "Wake on LAN" { Text("Sends a standard magic packet over UDP port 9. Broadcast may require Apple’s multicast entitlement and may be blocked by the network. Sending does not confirm that the target woke up.") }
            }
            if mode == "TCP monitor" {
                Section(model.saved.signalTarget.isEmpty ? "Connection history" : model.saved.signalTarget) {
                    SignalChart(points: model.saved.signal, unit: "ms", bluetooth: false).frame(height: 190)
                    Text(model.monitoring ? "Live · one probe per cycle" : "Saved measurements · paused").font(.caption).foregroundStyle(.secondary)
                    let values = model.saved.signal.compactMap(\.value)
                    if !values.isEmpty { LabeledContent("Average", value: "\(Int(values.reduce(0, +) / Double(values.count))) ms"); LabeledContent("No response", value: "\(model.saved.signal.count - values.count) of \(model.saved.signal.count)") }
                }
            }
            if !model.output.isEmpty && mode != "TCP monitor" {
                Section("Result") { Text(model.output).font(.system(.subheadline, design: .monospaced)).textSelection(.enabled) }
            }
        }
        .navigationTitle("Network tools")
        .toolbar { ShareLink(item: model.output) { Label("Export result", systemImage: "square.and.arrow.up") } }
        .onDisappear { model.persist() }
    }
    @ViewBuilder private var toolActions: some View {
        if mode == "TCP monitor" {
            ActionButton(model.monitoring ? "Stop monitoring" : "Start monitoring", systemImage: model.monitoring ? "stop.circle" : "waveform.path") { model.monitoring ? model.stopSignal() : model.startSignal() }
        } else if model.running {
            ActionButton("Stop", systemImage: "stop.circle") { model.stop() }
        } else {
            if mode == "Ports" { ActionButton("Check ports", systemImage: "network") { model.runPorts() } }
            if mode == "DNS" { ActionButton("Resolve addresses", systemImage: "globe") { model.runDNS() }; Button("Find reverse DNS name") { model.runDNS(reverse: true) } }
            if mode == "Registration" { ActionButton("Look up registration", systemImage: "doc.text.magnifyingglass") { model.runRDAP() } }
            if mode == "Wake on LAN" { ActionButton("Send wake packet", systemImage: "power") {
                do { try NetworkEngine.wake(mac: mac, destination: broadcast); model.output = "Wake packet sent to \(broadcast), UDP 9.\nTarget MAC: \(mac)\n\nDelivery and wake status are not confirmed."; model.record("Wake on LAN", model.output) }
                catch { model.error = error.localizedDescription }
            } }
        }
    }
}

private struct NearbyView: View {
    @EnvironmentObject private var finder: BluetoothFinder
    var body: some View {
        List {
            Section {
                NavigationLink { PrecisionView() } label: {
                    Label { VStack(alignment: .leading) { Text("Precision finder").font(.headline); Text("Check UWB support and pair two iPhones").font(.caption).foregroundStyle(.secondary) } } icon: { Image(systemName: "location.north.circle.fill").font(.title) }
                }
            }
            if let target = finder.target {
                Section("\(target.name)") {
                    HStack(alignment: .firstTextBaseline) { Text("\(target.rssi)").font(.system(size: 44, weight: .semibold, design: .rounded)); Text("dBm").foregroundStyle(.secondary); Spacer(); Text(trend(target.rssi)).font(.headline).foregroundStyle(.teal) }
                    Text("Last observed \(target.seen.formatted(date: .omitted, time: .standard))").font(.caption).foregroundStyle(.secondary)
                    SignalChart(points: target.history, unit: "dBm", bluetooth: true).frame(height: 140)
                    Button("Set baseline here") { finder.resetBaseline() }
                }
            }
            Section("Bluetooth LE signal finder") {
                ActionButton(finder.scanning ? "Stop scanning" : "Scan nearby", systemImage: finder.scanning ? "stop.circle.fill" : "dot.radiowaves.left.and.right") { finder.scanning ? finder.stop() : finder.start() }
                Text(finder.status).font(.caption).foregroundStyle(.secondary)
            } footer: { Text("Signal strength helps compare positions. Walls, body position and interference affect it; it cannot supply reliable meters or a direction arrow. BLE identifiers do not identify matching LAN devices.") }
            Section("\(finder.devices.count) observed devices") {
                ForEach(finder.devices.sorted(by: { $0.rssi > $1.rssi })) { device in
                    Button { finder.select(device) } label: {
                        HStack {
                            VStack(alignment: .leading, spacing: 4) { Text(device.name).font(.headline); Text(device.id.uuidString.prefix(8) + " · " + device.seen.formatted(date: .omitted, time: .shortened)).font(.caption).foregroundStyle(.secondary); TagPill(text: "Bluetooth LE") }
                            Spacer(); Text("\(device.rssi) dBm").monospacedDigit().foregroundStyle(.secondary)
                            if finder.selected == device.id { Image(systemName: "checkmark.circle.fill").foregroundStyle(.teal) }
                        }
                    }.buttonStyle(.plain)
                }
                if finder.devices.isEmpty { Text("Choose a discovered device to follow its signal. Devices must broadcast Bluetooth LE advertisements to appear.").foregroundStyle(.secondary) }
            }
        }.navigationTitle("Find nearby")
    }
    private func trend(_ value: Int) -> String {
        guard finder.scanning, let date = finder.target?.seen, Date().timeIntervalSince(date) < 8 else { return "Saved signal" }
        guard let baseline = finder.baseline else { return "Live signal" }
        let difference = value - baseline
        return difference > 3 ? "Stronger +\(difference) dB" : difference < -3 ? "Weaker \(difference) dB" : "Similar signal"
    }
}

private struct PrecisionView: View {
    @EnvironmentObject private var finder: PrecisionFinder
    @State private var code = ""
    @State private var showingCode = false
    var body: some View {
        List {
            Section {
                Label(finder.supported ? "Precision ranging available" : "Unsupported on this phone", systemImage: finder.supported ? "checkmark.circle.fill" : "exclamationmark.circle").font(.headline).foregroundStyle(finder.supported ? .teal : .secondary)
                Text(finder.status).font(.subheadline)
                if finder.supported { Text(finder.directionSupported ? "Direction and precise distance supported" : "Precise distance only; direction unsupported").font(.caption).foregroundStyle(.secondary) }
            } footer: { Text("Uses Apple Nearby Interaction between two compatible iPhones running FieldKit. Both people approve pairing and keep the app open. AirTags, commercial trackers and the Android app use other protocols and are not paired here.") }
            if finder.supported {
                if let distance = finder.distance {
                    Section("Live ranging") {
                        VStack(spacing: 12) {
                            TimelineView(.periodic(from: .now, by: 0.5)) { timeline in
                                let fresh = finder.measuredAt.map { timeline.date.timeIntervalSince($0) < 3 } ?? false
                                if fresh {
                                    if let angle = finder.azimuth {
                                        Image(systemName: "arrow.up.circle.fill").font(.system(size: 100)).foregroundStyle(.teal).rotationEffect(.radians(angle)).accessibilityLabel("Target bearing \(Int(angle * 180 / .pi)) degrees relative to the rear-camera facing direction")
                                    } else { Image(systemName: "dot.radiowaves.left.and.right").font(.system(size: 70)).foregroundStyle(.secondary) }
                                    Text(String(format: "%.2f m", distance)).font(.system(size: 44, weight: .semibold, design: .rounded))
                                    Text(finder.azimuth == nil ? "Direction unavailable" : "Hold upright · up means straight ahead of the rear camera").font(.caption).foregroundStyle(.secondary)
                                    if let elevation = finder.elevation { Text("Elevation \(Int(elevation * 180 / .pi))°").font(.caption).foregroundStyle(.secondary) }
                                } else { Label("Measurement stale · searching", systemImage: "clock").foregroundStyle(.secondary) }
                            }
                        }.frame(maxWidth: .infinity).padding(.vertical, 12)
                    }
                }
                if finder.active {
                    if finder.hosting {
                        Section("Private pairing code") {
                            Text(finder.pairingCode).font(.system(.body, design: .monospaced)).textSelection(.enabled)
                            ShareLink(item: finder.pairingCode) { Label("Share code privately", systemImage: "square.and.arrow.up") }
                            Text("Your temporary device name: \(finderDeviceName)").font(.caption).foregroundStyle(.secondary)
                            Text("Only share with the intended person. The code authenticates the encrypted session and expires when you stop.").font(.caption).foregroundStyle(.secondary)
                        }
                    }
                    if !finder.peers.isEmpty { Section("Choose the other phone") { ForEach(finder.peers, id: \.self) { peer in Button(peer.displayName) { finder.connect(peer) } } } }
                    Section { Button("Stop and forget session", role: .destructive) { finder.stop() } }
                } else {
                    Section {
                        ActionButton("Make this phone discoverable", systemImage: "iphone.radiowaves.left.and.right") { finder.host() }
                        TextField("Paste private code from other phone", text: $code).textInputAutocapitalization(.never).autocorrectionDisabled()
                        ActionButton("Find the other phone", systemImage: "magnifyingglass") { finder.browse(code: code) }
                    }
                }
            } else { Section { Button("Check support again") { finder.checkSupport() } } }
        }
        .navigationTitle("Precision finder").navigationBarTitleDisplayMode(.inline)
        .alert("Allow this phone to pair?", isPresented: Binding(get: { finder.incomingName != nil }, set: { if !$0 { finder.approve(false) } })) {
            Button("Decline", role: .cancel) { finder.approve(false) }; Button("Allow") { finder.approve(true) }
        } message: { Text("\(finder.incomingName ?? "A nearby phone") wants to start a private ranging session. Only allow the person you shared the code with.") }
        .onDisappear { if finder.active { finder.stop() } }
    }
    private var finderDeviceName: String { finder.localDisplayName }
}

private struct SettingsView: View {
    @EnvironmentObject private var model: AppModel
    @EnvironmentObject private var finder: BluetoothFinder
    @State private var confirmClear = false
    var body: some View {
        List {
            Section("Appearance") { Picker("Theme", selection: $model.saved.theme) { Text("System").tag("system"); Text("Light").tag("light"); Text("Dark").tag("dark") }.onChange(of: model.saved.theme) { _ in model.persist() } }
            Section("Saved on this device") {
                NavigationLink("History · \(model.saved.history.count) runs") { List(model.saved.history) { record in NavigationLink { ScrollView { Text(record.text).font(.system(.subheadline, design: .monospaced)).frame(maxWidth: .infinity, alignment: .leading).padding().textSelection(.enabled) }.navigationTitle(record.title).toolbar { ShareLink(item: record.text) { Image(systemName: "square.and.arrow.up") } } } label: { VStack(alignment: .leading) { Text(record.title); Text(record.date.formatted()).font(.caption).foregroundStyle(.secondary) } } }.navigationTitle("History") }
                Text("LAN results, connection charts and Bluetooth observations remain after navigating back or closing the app. Saved results show their observation time; scans never restart themselves.").font(.footnote).foregroundStyle(.secondary)
                Button("Clear saved results", role: .destructive) { confirmClear = true }
                Button("Clear history", role: .destructive) { model.saved.history = []; model.persist() }
            }
            Section("FieldKit 1.0.0") {
                Text("Local diagnostics without an account. There are no analytics or background scans. Registration lookups contact public RDAP services only when requested.").font(.footnote)
                Text("iOS 16 or later. Wi-Fi surveys, cellular signal strength, raw packet capture, ARP inventory and traceroute are not available through the public APIs used by this release.").font(.footnote).foregroundStyle(.secondary)
                NavigationLink("App license") {
                    ScrollView {
                        Text(appLicense).font(.system(.footnote, design: .monospaced)).frame(maxWidth: .infinity, alignment: .leading).padding().textSelection(.enabled)
                    }.navigationTitle("MIT license")
                }
            }
        }.navigationTitle("Settings")
        .confirmationDialog("Delete saved LAN results, signal charts and Bluetooth observations? History remains available.", isPresented: $confirmClear, titleVisibility: .visible) { Button("Delete saved results", role: .destructive) { model.clearRetained(); finder.clear() } }
    }
    private var appLicense: String {
        guard let url = Bundle.main.url(forResource: "LICENSE", withExtension: "txt"), let text = try? String(contentsOf: url, encoding: .utf8) else { return "License could not be loaded." }
        return text
    }
}

private struct SignalChart: View {
    let points: [SignalPoint]
    let unit: String
    let bluetooth: Bool
    var body: some View {
        if points.isEmpty {
            VStack(spacing: 8) { Image(systemName: "waveform.path").font(.title); Text("Start to collect measurements").font(.caption) }.foregroundStyle(.secondary).frame(maxWidth: .infinity, maxHeight: .infinity)
        } else {
            Chart(points) { point in
                if let value = point.value { PointMark(x: .value("Time", point.date), y: .value(unit, value)).foregroundStyle(.teal).symbolSize(18) }
                else { RuleMark(x: .value("No response", point.date)).foregroundStyle(.orange.opacity(0.35)).lineStyle(StrokeStyle(lineWidth: 1, dash: [2, 2])) }
            }
            .chartYScale(domain: bluetooth ? -110.0 ... -15.0 : 0.0 ... max(10, (points.compactMap(\.value).max() ?? 10) * 1.1))
            .chartYAxisLabel(unit)
            .accessibilityLabel("\(points.count) saved measurements in \(unit). Orange markers mean no response.")
        }
    }
}

private struct ActionButton: View {
    let title: String
    let systemImage: String
    let action: () -> Void
    init(_ title: String, systemImage: String, action: @escaping () -> Void) {
        self.title = title; self.systemImage = systemImage; self.action = action
    }
    var body: some View { Button(action: action) { Label(title, systemImage: systemImage) } }
}

private struct TagPill: View {
    let text: String
    private var color: Color { ["IPv4":.blue, "IPv6":.purple, "This device":.teal, "TCP open":.green, "Bonjour":.orange, "Bluetooth LE":.indigo][text] ?? .secondary }
    var body: some View { Text(text).font(.system(size: 10, weight: .semibold)).padding(.horizontal, 6).padding(.vertical, 3).foregroundStyle(color).background(color.opacity(0.13), in: Capsule()).accessibilityLabel(text) }
}

private struct TagLayout: Layout {
    var spacing: CGFloat = 4
    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize { arrange(width: proposal.width ?? 300, subviews: subviews).size }
    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        let result = arrange(width: bounds.width, subviews: subviews)
        for (index, point) in result.points.enumerated() { subviews[index].place(at: CGPoint(x: bounds.minX + point.x, y: bounds.minY + point.y), proposal: .unspecified) }
    }
    private func arrange(width: CGFloat, subviews: Subviews) -> (size: CGSize, points: [CGPoint]) {
        var x: CGFloat = 0; var y: CGFloat = 0; var rowHeight: CGFloat = 0; var points: [CGPoint] = []
        for view in subviews {
            let size = view.sizeThatFits(.unspecified)
            if x > 0 && x + size.width > width { x = 0; y += rowHeight + spacing; rowHeight = 0 }
            points.append(CGPoint(x: x, y: y)); x += size.width + spacing; rowHeight = max(rowHeight, size.height)
        }
        return (CGSize(width: width, height: y + rowHeight), points)
    }
}
