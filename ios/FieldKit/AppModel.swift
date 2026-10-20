import Foundation
import Network
import SwiftUI

struct SavedWorkspace: Codable {
    var subnet = ""
    var target = ""
    var ports = "22,80,443,445,8080"
    var route = ""
    var devices: [LANDevice] = []
    var lanDate: Date?
    var signal: [SignalPoint] = []
    var signalTarget = ""
    var history: [ToolRecord] = []
    var theme = "system"
}

@MainActor
final class AppModel: ObservableObject {
    @Published var saved = SavedWorkspace()
    @Published var addresses: [NetworkAddress] = []
    @Published var pathStatus = "Checking connectivity…"
    @Published var running = false
    @Published var monitoring = false
    @Published var progress = ""
    @Published var error: String?
    @Published var output = ""
    @Published var selectedTab = 0
    private let monitor = NWPathMonitor()
    private var path: NWPath?
    private let queue = DispatchQueue(label: "com.fieldkit.path")
    private var work: Task<Void, Never>?
    private var signalWork: Task<Void, Never>?
    private var discovery = BonjourDiscovery()
    private var generation = UUID()
    private let file = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent("FieldKit/workspace.json")

    init() {
        if let data = try? Data(contentsOf: file), data.count < 8_000_000,
           let value = try? JSONDecoder().decode(SavedWorkspace.self, from: data) { saved = value }
        refresh()
        discovery.found = { [weak self] address, name, service in self?.mergeBonjour(address: address, name: name, service: service) }
        discovery.status = { [weak self] status in if self?.running == true { self?.progress = status } }
        monitor.pathUpdateHandler = { [weak self] path in
            Task { @MainActor in
                self?.path = path
                self?.pathStatus = path.status == .satisfied ? (path.isExpensive ? "Connected · metered path" : "Connected") : "No active default path"
                self?.refresh()
            }
        }
        monitor.start(queue: queue)
    }
    var suggestedSubnets: [String] { Array(Set(addresses.compactMap(\.subnet))).sorted() }
    var suggestedHosts: [String] { Array(Set(addresses.map(\.address) + saved.devices.map(\.address))).sorted() }
    var routeNames: [String] { Array(Set((path?.availableInterfaces ?? []).map(\.name))).sorted() }
    var routeDescription: String { saved.route.isEmpty ? "System routing, including any VPN" : "Explicit interface: \(saved.route). VPN policy may block this route." }
    var colorScheme: ColorScheme? { saved.theme == "dark" ? .dark : saved.theme == "light" ? .light : nil }
    private var route: NWInterface? { path?.availableInterfaces.first { $0.name == saved.route } }

    func refresh() {
        addresses = InterfaceInventory.addresses()
        if saved.subnet.isEmpty { saved.subnet = addresses.first(where: { $0.kind == "Wi-Fi" && $0.subnet != nil })?.subnet ?? suggestedSubnets.first ?? "192.168.1.0/24" }
        if saved.target.isEmpty { saved.target = addresses.first(where: { $0.kind == "Wi-Fi" && !$0.isIPv6 })?.address ?? "" }
    }
    func persist() {
        guard let data = try? JSONEncoder().encode(saved) else { return }
        do {
            try FileManager.default.createDirectory(at: file.deletingLastPathComponent(), withIntermediateDirectories: true)
            try data.write(to: file, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        } catch { self.error = "Could not save results: \(error.localizedDescription)" }
    }
    func record(_ title: String, _ text: String) {
        let retained = text.count > 30_000 ? String(text.prefix(30_000)) + "\n\nHistory preview shortened. Export the current result for the full report." : text
        saved.history.insert(ToolRecord(title: title, text: retained), at: 0)
        if saved.history.count > 50 { saved.history.removeLast(saved.history.count - 50) }
        while saved.history.count > 1 && saved.history.reduce(0, { $0 + $1.text.utf8.count }) > 1_000_000 { saved.history.removeLast() }
        persist()
    }
    func stop() {
        generation = UUID(); work?.cancel(); work = nil; discovery.stop(); running = false
        progress = "Stopped. Discovered devices are saved."; persist()
    }
    func background() { stop(); stopSignal(); persist() }
    func clearRetained() { stop(); stopSignal(); saved.devices = []; saved.lanDate = nil; saved.signal = []; persist() }

    func scanLAN() {
        stop()
        let subnet: IPv4Subnet
        do { subnet = try IPv4Subnet(saved.subnet) }
        catch { self.error = error.localizedDescription; return }
        guard saved.route.isEmpty || route != nil else { error = "The selected interface is no longer available. Choose System routing or a connected interface."; return }
        saved.subnet = subnet.description; saved.devices = []; saved.lanDate = Date(); running = true
        let own = Set(addresses.map(\.address))
        let selectedRoute = route
        let token = UUID(); generation = token
        let hosts = subnet.hosts
        let quick: [UInt16] = [22, 80, 443, 445]
        progress = "Checking \(hosts.count) addresses…"
        discovery.start()
        work = Task { [weak self] in
            guard let self else { return }
            await withTaskGroup(of: LANDevice?.self) { group in
                var iterator = hosts.makeIterator()
                func enqueue(_ host: String) {
                    group.addTask {
                        guard !Task.isCancelled else { return nil }
                        var open: [UInt16] = []
                        for port in quick {
                            if Task.isCancelled { return nil }
                            if await NetworkEngine.probe(host: host, port: port, interface: selectedRoute, timeout: 0.35).open { open.append(port) }
                        }
                        guard !open.isEmpty || own.contains(host) else { return nil }
                        let remaining = PortSpec.common.filter { !quick.contains($0) }
                        for port in remaining {
                            if Task.isCancelled { break }
                            if await NetworkEngine.probe(host: host, port: port, interface: selectedRoute, timeout: 0.3).open { open.append(port) }
                        }
                        let name = await NetworkEngine.reverseName(host)
                        return LANDevice(address: host, name: name, nameSource: name.isEmpty ? "" : "System reverse DNS", openPorts: open.sorted(), isThisDevice: own.contains(host))
                    }
                }
                for _ in 0..<min(32, hosts.count) { if let host = iterator.next() { enqueue(host) } }
                var completed = 0
                while let result = await group.next() {
                    guard !Task.isCancelled, self.generation == token else { group.cancelAll(); return }
                    completed += 1
                    if let device = result { self.merge(device); self.persist() }
                    self.progress = "\(completed) of \(hosts.count) addresses checked · \(self.saved.devices.count) devices"
                    if let host = iterator.next() { enqueue(host) }
                }
            }
            guard !Task.isCancelled, self.generation == token else { return }
            self.running = false
            self.progress = "Scan complete · \(self.saved.devices.count) devices. Devices with no open probe ports or Bonjour advertisements may stay hidden."
            self.record("LAN · \(subnet.description)", self.lanText)
        }
    }
    private func merge(_ device: LANDevice) {
        if let index = saved.devices.firstIndex(where: { $0.address == device.address }) {
            var combined = device
            if combined.name.isEmpty { combined.name = saved.devices[index].name; combined.nameSource = saved.devices[index].nameSource }
            combined.advertisedServices = Array(Set(combined.advertisedServices + saved.devices[index].advertisedServices)).sorted()
            combined.openPorts = Array(Set(combined.openPorts + saved.devices[index].openPorts)).sorted()
            saved.devices[index] = combined
        } else { saved.devices.append(device) }
        saved.devices.sort { (IPv4Subnet.parse($0.address) ?? UInt32.max, $0.address) < (IPv4Subnet.parse($1.address) ?? UInt32.max, $1.address) }
    }
    private func mergeBonjour(address: String, name: String, service: String) {
        // Keep only the selected IPv4 subnet; IPv6 advertisements are retained as separate evidence, never invented dual-stack matches.
        guard let subnet = try? IPv4Subnet(saved.subnet) else { return }
        if let ipv4 = IPv4Subnet.parse(address) {
            let mask = subnet.prefix == 0 ? 0 : UInt32.max << (32 - subnet.prefix)
            guard ipv4 & mask == subnet.network else { return }
        }
        var device = saved.devices.first { $0.address == address } ?? LANDevice(address: address)
        device.name = name; device.nameSource = "Bonjour service name"
        device.isThisDevice = addresses.contains { $0.address == address }
        device.advertisedServices = Array(Set(device.advertisedServices + [service])).sorted(); device.observedAt = Date()
        merge(device); persist()
    }
    var lanText: String {
        saved.devices.map { device in
            "\(device.displayName)\n\(device.address) · \(device.tags.joined(separator: ", "))\nOpen TCP: \(device.openPorts.isEmpty ? "none confirmed" : device.openPorts.map { "\($0) \(PortSpec.service($0))" }.joined(separator: ", "))\nName source: \(device.nameSource.isEmpty ? "not published" : device.nameSource)\nAdvertised: \(device.advertisedServices.joined(separator: ", "))"
        }.joined(separator: "\n\n")
    }

    func runPorts() {
        stop()
        let ports: [UInt16]
        do { ports = try PortSpec.parse(saved.ports) } catch { self.error = error.localizedDescription; return }
        let target = saved.target.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !target.isEmpty else { error = "Choose or enter a host address."; return }
        guard saved.route.isEmpty || route != nil else { error = "The selected interface disappeared. Choose another route."; return }
        let selectedRoute = route
        running = true; output = "Checking \(ports.count) TCP ports on \(target)…"
        work = Task {
            let results = await NetworkEngine.scanPorts(host: target, ports: ports, interface: selectedRoute)
            guard !Task.isCancelled else { return }
            let open = results.filter(\.open)
            output = "\(open.count) open TCP port\(open.count == 1 ? "" : "s") on \(target)\n\n" + results.map { result in
                result.open ? "\(result.port) · \(PortSpec.service(result.port)) · Open · \(Int(result.milliseconds ?? 0)) ms" : "\(result.port) · \(PortSpec.service(result.port)) · Not confirmed open\n  \(result.error ?? "No response")"
            }.joined(separator: "\n")
            running = false; record("Ports · \(target)", output)
        }
    }
    func runDNS(reverse: Bool = false) {
        stop(); let target = saved.target.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !target.isEmpty else { error = "Choose or enter a host."; return }
        running = true; output = "Querying the system resolver…"
        work = Task {
            let result = await NetworkEngine.resolve(target, reverse: reverse)
            guard !Task.isCancelled else { return }
            output = "\(reverse ? "Reverse DNS" : "System DNS") · \(target)\n\n\(result)\n\nThe system resolver follows iOS and VPN DNS policy."
            running = false; record("DNS · \(target)", output)
        }
    }
    func runRDAP() {
        stop(); let target = saved.target.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !target.isEmpty, !target.contains("/"), !target.contains("?"), !target.contains("#") else { error = "Enter a domain or IP address."; return }
        let kind = IPv4Subnet.parse(target) != nil || target.contains(":") ? "ip" : "domain"
        guard let encoded = target.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed), let url = URL(string: "https://rdap.org/\(kind)/\(encoded)") else { return }
        running = true; output = "Requesting public registration data…"
        work = Task {
            do {
                var request = URLRequest(url: url); request.timeoutInterval = 15
                request.setValue("application/rdap+json, application/json", forHTTPHeaderField: "Accept")
                let (data, response) = try await URLSession.shared.data(for: request)
                guard !Task.isCancelled else { return }
                guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode), data.count < 2_000_000 else { throw InputError.invalid("Registration service returned no usable result.") }
                let summary = try RegistrationSummary.text(from: data)
                output = "Registration · \(target)\nSource: \(response.url?.host ?? "rdap.org")\n\n" + summary
                record("RDAP · \(target)", output)
            } catch { if !Task.isCancelled { output = "Registration lookup failed: \(error.localizedDescription)" } }
            running = false
        }
    }
    func startSignal() {
        stopSignal()
        let target = saved.target.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !target.isEmpty else { error = "Choose a target first."; return }
        guard saved.route.isEmpty || route != nil else { error = "The selected interface disappeared. Choose another route."; return }
        guard let port = try? PortSpec.parse(saved.ports).first else { error = "Enter at least one valid TCP port."; return }
        saved.signalTarget = "\(target):\(port)"; saved.signal = []; monitoring = true
        let selectedRoute = route
        signalWork = Task {
            while !Task.isCancelled {
                let result = await NetworkEngine.probe(host: target, port: port, interface: selectedRoute, timeout: 2)
                guard !Task.isCancelled else { break }
                saved.signal.append(SignalPoint(value: result.milliseconds))
                if saved.signal.count > 180 { saved.signal.removeFirst(saved.signal.count - 180) }
                persist()
                try? await Task.sleep(nanoseconds: 1_000_000_000)
            }
        }
    }
    func stopSignal() { signalWork?.cancel(); signalWork = nil; monitoring = false; persist() }
}
