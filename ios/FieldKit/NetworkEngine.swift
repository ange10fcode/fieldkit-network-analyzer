import Foundation
import Network
import Darwin

struct NetworkAddress: Identifiable, Codable, Equatable {
    var id: String { "\(interface):\(address)" }
    let interface: String
    let kind: String
    let address: String
    let prefix: Int
    var isIPv6: Bool { address.contains(":") }
    var subnet: String? { isIPv6 ? nil : (try? IPv4Subnet("\(address)/\(prefix)").description) }
}

enum InterfaceInventory {
    static func addresses() -> [NetworkAddress] {
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let first = head else { return [] }
        defer { freeifaddrs(head) }
        var result: [NetworkAddress] = []
        var item: UnsafeMutablePointer<ifaddrs>? = first
        while let current = item {
            defer { item = current.pointee.ifa_next }
            let entry = current.pointee
            guard let address = entry.ifa_addr,
                  entry.ifa_flags & UInt32(IFF_UP) != 0,
                  entry.ifa_flags & UInt32(IFF_LOOPBACK) == 0,
                  address.pointee.sa_family == UInt8(AF_INET) || address.pointee.sa_family == UInt8(AF_INET6) else { continue }
            let name = String(cString: entry.ifa_name)
            let kind: String
            if name.hasPrefix("utun") || name.hasPrefix("ipsec") || name.hasPrefix("ppp") { kind = "VPN/tunnel" }
            else if name.hasPrefix("pdp_ip") { kind = "Cellular" }
            else if name == "en0" { kind = "Wi-Fi" }
            else if name.hasPrefix("awdl") || name.hasPrefix("llw") { kind = "Peer-to-peer Wi-Fi" }
            else { kind = "Ethernet/other" }
            let family = Int32(address.pointee.sa_family)
            let length = family == AF_INET ? socklen_t(MemoryLayout<sockaddr_in>.size) : socklen_t(MemoryLayout<sockaddr_in6>.size)
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            guard getnameinfo(address, length, &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 else { continue }
            var prefix = family == AF_INET ? 32 : 128
            if let mask = entry.ifa_netmask {
                if family == AF_INET {
                    let value = UnsafeRawPointer(mask).assumingMemoryBound(to: sockaddr_in.self).pointee.sin_addr.s_addr.bigEndian
                    prefix = value.nonzeroBitCount
                } else {
                    var mask6 = UnsafeRawPointer(mask).assumingMemoryBound(to: sockaddr_in6.self).pointee.sin6_addr
                    prefix = withUnsafeBytes(of: &mask6) { $0.reduce(0) { $0 + $1.nonzeroBitCount } }
                }
            }
            result.append(NetworkAddress(interface: name, kind: kind, address: String(cString: host), prefix: prefix))
        }
        return result.sorted { ($0.kind, $0.interface, $0.address) < ($1.kind, $1.interface, $1.address) }
    }

    static func numericAddress(_ data: Data) -> String? {
        data.withUnsafeBytes { buffer -> String? in
            guard let base = buffer.baseAddress, buffer.count >= MemoryLayout<sockaddr>.size else { return nil }
            let address = base.assumingMemoryBound(to: sockaddr.self)
            let family = Int32(address.pointee.sa_family)
            guard family == AF_INET || family == AF_INET6 else { return nil }
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            guard getnameinfo(address, socklen_t(buffer.count), &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 else { return nil }
            return String(cString: host)
        }
    }
}

struct ProbeResult: Sendable {
    let port: UInt16
    let milliseconds: Double?
    let error: String?
    var open: Bool { milliseconds != nil }
}

private final class ProbeOperation: @unchecked Sendable {
    private let lock = NSLock()
    private var completed = false
    private var connection: NWConnection?
    private let queue = DispatchQueue(label: "com.fieldkit.probe", qos: .utility)
    private let start = Date()
    private let port: UInt16
    private let continuation: CheckedContinuation<ProbeResult, Never>
    init(host: String, port: UInt16, interface: NWInterface?, timeout: Double, continuation: CheckedContinuation<ProbeResult, Never>) {
        self.port = port; self.continuation = continuation
        let parameters = NWParameters.tcp
        parameters.requiredInterface = interface
        parameters.allowLocalEndpointReuse = true
        let connection = NWConnection(host: NWEndpoint.Host(host), port: NWEndpoint.Port(rawValue: port)!, using: parameters)
        self.connection = connection
        connection.stateUpdateHandler = { [self] state in
            switch state {
            case .ready: finish(ProbeResult(port: port, milliseconds: max(0, Date().timeIntervalSince(start) * 1000), error: nil))
            case .failed(let error): finish(ProbeResult(port: port, milliseconds: nil, error: error.localizedDescription))
            case .cancelled: finish(ProbeResult(port: port, milliseconds: nil, error: "Cancelled"))
            default: break
            }
        }
        connection.start(queue: queue)
        queue.asyncAfter(deadline: .now() + timeout) { [self] in
            finish(ProbeResult(port: port, milliseconds: nil, error: "No TCP response before timeout"))
        }
    }
    private func finish(_ result: ProbeResult) {
        lock.lock()
        guard !completed else { lock.unlock(); return }
        completed = true
        let active = connection; connection = nil
        lock.unlock()
        active?.stateUpdateHandler = nil
        active?.cancel()
        continuation.resume(returning: result)
    }
}

enum NetworkEngine {
    static func probe(host: String, port: UInt16, interface: NWInterface? = nil, timeout: Double = 0.7) async -> ProbeResult {
        if Task.isCancelled { return ProbeResult(port: port, milliseconds: nil, error: "Cancelled") }
        return await withCheckedContinuation { continuation in
            _ = ProbeOperation(host: host, port: port, interface: interface, timeout: timeout, continuation: continuation)
        }
    }

    static func scanPorts(host: String, ports: [UInt16], interface: NWInterface?) async -> [ProbeResult] {
        await withTaskGroup(of: ProbeResult.self) { group in
            var next = ports.makeIterator()
            for _ in 0..<min(16, ports.count) {
                if let port = next.next() { group.addTask { await probe(host: host, port: port, interface: interface) } }
            }
            var results: [ProbeResult] = []
            while let result = await group.next() {
                results.append(result)
                if !Task.isCancelled, let port = next.next() { group.addTask { await probe(host: host, port: port, interface: interface) } }
            }
            return results.sorted { $0.port < $1.port }
        }
    }

    static func resolve(_ host: String, reverse: Bool = false) async -> String {
        await Task.detached(priority: .utility) {
            var hints = addrinfo()
            hints.ai_family = AF_UNSPEC
            hints.ai_socktype = SOCK_STREAM
            var head: UnsafeMutablePointer<addrinfo>?
            let status = getaddrinfo(host, nil, &hints, &head)
            guard status == 0 else { return "Resolution failed: \(String(cString: gai_strerror(status)))" }
            defer { freeaddrinfo(head) }
            var values = Set<String>()
            var item = head
            while let current = item {
                defer { item = current.pointee.ai_next }
                guard let address = current.pointee.ai_addr else { continue }
                var name = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                let flags = reverse ? NI_NAMEREQD : NI_NUMERICHOST
                if getnameinfo(address, current.pointee.ai_addrlen, &name, socklen_t(name.count), nil, 0, flags) == 0 { values.insert(String(cString: name)) }
            }
            return values.isEmpty ? "No \(reverse ? "published reverse name" : "address") returned by the system resolver." : values.sorted().joined(separator: "\n")
        }.value
    }

    static func reverseName(_ address: String) async -> String {
        let result = await resolve(address, reverse: true)
        guard !result.contains("\n"), !result.hasPrefix("No "), !result.hasPrefix("Resolution failed"), result != address else { return "" }
        return result
    }

    static func wake(mac: String, destination: String) throws {
        let data = try WakePacket.make(mac: mac)
        guard IPv4Subnet.parse(destination) != nil else { throw InputError.invalid("Enter an IPv4 destination or directed broadcast address.") }
        let fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        guard fd >= 0 else { throw InputError.invalid("Unable to open a UDP socket.") }
        defer { close(fd) }
        var enabled: Int32 = 1
        guard setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &enabled, socklen_t(MemoryLayout.size(ofValue: enabled))) == 0 else { throw InputError.invalid("Broadcast is unavailable on this network.") }
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = UInt16(9).bigEndian
        guard inet_pton(AF_INET, destination, &address.sin_addr) == 1 else { throw InputError.invalid("Invalid destination.") }
        let sent = data.withUnsafeBytes { bytes in
            withUnsafePointer(to: &address) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { target in
                    sendto(fd, bytes.baseAddress, bytes.count, 0, target, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }
        guard sent == data.count else { throw InputError.invalid("Wake packet was not sent: \(String(cString: strerror(errno))). Check Local Network permission and broadcast routing.") }
    }
}
