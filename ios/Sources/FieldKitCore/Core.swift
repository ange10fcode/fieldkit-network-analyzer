import Foundation

public enum InputError: LocalizedError {
    case invalid(String)
    public var errorDescription: String? {
        switch self { case .invalid(let message): return message }
    }
}

public struct IPv4Subnet: Equatable, Sendable {
    public let network: UInt32
    public let prefix: Int
    public init(_ text: String, limit: Int = 4096) throws {
        let parts = text.trimmingCharacters(in: .whitespacesAndNewlines).split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 2, let address = Self.parse(String(parts[0])), let bits = Int(parts[1]), (0...32).contains(bits) else {
            throw InputError.invalid("Enter an IPv4 network such as 192.168.1.0/24.")
        }
        let count = UInt64(1) << (32 - bits)
        guard count <= UInt64(max(1, limit)) else { throw InputError.invalid("Choose a smaller network: at most \(limit) addresses per scan.") }
        prefix = bits
        network = address & (bits == 0 ? 0 : UInt32.max << (32 - bits))
    }
    public var description: String { "\(Self.format(network))/\(prefix)" }
    public var hosts: [String] {
        let size = Int(UInt64(1) << (32 - prefix))
        let first = size > 2 ? 1 : 0
        let last = size > 2 ? size - 1 : size
        return (first..<last).map { Self.format(network + UInt32($0)) }
    }
    public static func parse(_ text: String) -> UInt32? {
        let parts = text.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var value: UInt32 = 0
        for part in parts {
            guard !part.isEmpty, part.allSatisfy({ $0.isASCII && $0.isNumber }), let byte = UInt8(part) else { return nil }
            value = (value << 8) | UInt32(byte)
        }
        return value
    }
    public static func format(_ value: UInt32) -> String {
        [24, 16, 8, 0].map { String((value >> $0) & 255) }.joined(separator: ".")
    }
}

public enum PortSpec {
    public static let common: [UInt16] = [22, 53, 80, 139, 443, 445, 548, 554, 631, 1883, 3389, 5000, 5357, 8000, 8080, 8443, 9100]
    public static func parse(_ text: String, limit: Int = 128) throws -> [UInt16] {
        var values = Set<UInt16>()
        for segment in text.split(separator: ",", omittingEmptySubsequences: false) {
            let pair = segment.trimmingCharacters(in: .whitespaces).split(separator: "-", omittingEmptySubsequences: false)
            guard (1...2).contains(pair.count), let lower = UInt16(pair[0]), lower > 0 else { throw InputError.invalid("Use ports like 22,80,443 or 8000-8010.") }
            let upper = pair.count == 2 ? UInt16(pair[1]) : lower
            guard let upper, upper >= lower else { throw InputError.invalid("Port ranges must increase and stay within 1–65535.") }
            guard Int(upper) - Int(lower) < limit else { throw InputError.invalid("Scan at most \(limit) ports at once.") }
            for value in lower...upper { values.insert(value) }
            guard values.count <= limit else { throw InputError.invalid("Scan at most \(limit) ports at once.") }
        }
        return values.sorted()
    }
    public static func service(_ port: UInt16) -> String {
        let names: [UInt16: String] = [22:"SSH",53:"DNS",80:"HTTP",139:"NetBIOS",443:"HTTPS",445:"SMB",548:"AFP",554:"RTSP",631:"IPP",1883:"MQTT",3389:"RDP",5000:"HTTP/service",5357:"WSD",8000:"HTTP alternate",8080:"HTTP proxy",8443:"HTTPS alternate",9100:"Printing"]
        return names[port] ?? "TCP"
    }
}

public enum WakePacket {
    public static func make(mac: String) throws -> Data {
        let compact = mac.replacingOccurrences(of: ":", with: "").replacingOccurrences(of: "-", with: "")
        guard compact.count == 12, compact.allSatisfy({ $0.isHexDigit }) else { throw InputError.invalid("Enter a MAC address such as AA:BB:CC:DD:EE:FF.") }
        let bytes = stride(from: 0, to: 12, by: 2).compactMap { offset -> UInt8? in
            let start = compact.index(compact.startIndex, offsetBy: offset)
            return UInt8(compact[start..<compact.index(start, offsetBy: 2)], radix: 16)
        }
        guard bytes.count == 6 else { throw InputError.invalid("Invalid MAC address.") }
        var data = Data(repeating: 255, count: 6)
        for _ in 0..<16 { data.append(contentsOf: bytes) }
        return data
    }
}

public struct LANDevice: Identifiable, Codable, Equatable, Sendable {
    public var id: String { address }
    public var address: String
    public var name: String
    public var nameSource: String
    public var openPorts: [UInt16]
    public var advertisedServices: [String]
    public var isThisDevice: Bool
    public var observedAt: Date
    public init(address: String, name: String = "", nameSource: String = "", openPorts: [UInt16] = [], advertisedServices: [String] = [], isThisDevice: Bool = false, observedAt: Date = Date()) {
        self.address = address; self.name = name; self.nameSource = nameSource
        self.openPorts = openPorts; self.advertisedServices = advertisedServices
        self.isThisDevice = isThisDevice; self.observedAt = observedAt
    }
    public var displayName: String { name.isEmpty ? (isThisDevice ? "This iPhone" : "Unnamed device") : name }
    public var tags: [String] {
        var result = [address.contains(":") ? "IPv6" : "IPv4"]
        if isThisDevice { result.append("This device") }
        if !openPorts.isEmpty { result.append("TCP open") }
        if !advertisedServices.isEmpty { result.append("Bonjour") }
        return result
    }
}

public struct SignalPoint: Identifiable, Codable, Equatable, Sendable {
    public var id: UUID = UUID()
    public var date: Date
    public var value: Double?
    public init(date: Date = Date(), value: Double?) { self.date = date; self.value = value }
}

public struct ToolRecord: Identifiable, Codable, Sendable {
    public var id: UUID = UUID()
    public var date: Date = Date()
    public var title: String
    public var text: String
    public init(title: String, text: String) { self.title = title; self.text = text }
}

public enum RegistrationSummary {
    public static func text(from data: Data) throws -> String {
        guard let item = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw InputError.invalid("Registration response is not a JSON object.") }
        var lines: [String] = []
        for (key, title) in [("name", "Name"), ("ldhName", "Domain"), ("handle", "Handle"), ("type", "Type"), ("country", "Country"), ("startAddress", "First address"), ("endAddress", "Last address"), ("ipVersion", "IP version")] {
            if let value = item[key] as? String, !value.isEmpty { lines.append("\(title): \(value)") }
        }
        if let statuses = item["status"] as? [String], !statuses.isEmpty { lines.append("Status: " + statuses.joined(separator: ", ")) }
        if let nameservers = item["nameservers"] as? [[String: Any]] {
            let names = nameservers.compactMap { $0["ldhName"] as? String }
            if !names.isEmpty { lines.append("Name servers: " + names.joined(separator: ", ")) }
        }
        if let events = item["events"] as? [[String: Any]] {
            for event in events.prefix(20) {
                if let action = event["eventAction"] as? String, let date = event["eventDate"] as? String { lines.append("\(action.capitalized): \(date)") }
            }
        }
        if let entities = item["entities"] as? [[String: Any]] {
            for entity in entities.prefix(20) {
                let roles = (entity["roles"] as? [String])?.joined(separator: ", ") ?? "Contact"
                var name = entity["handle"] as? String ?? "Not published"
                if let vcard = entity["vcardArray"] as? [Any], vcard.count == 2, let fields = vcard[1] as? [[Any]],
                   let fullName = fields.first(where: { ($0.first as? String) == "fn" }), fullName.count >= 4,
                   let value = fullName[3] as? String { name = value }
                lines.append("\(roles.capitalized): \(name)")
            }
        }
        if let notices = item["notices"] as? [[String: Any]] {
            for notice in notices.prefix(8) {
                if let title = notice["title"] as? String { lines.append("\n\(title)") }
                if let description = notice["description"] as? [String] { lines.append(contentsOf: description.prefix(5)) }
            }
        }
        return lines.isEmpty ? "The service returned no public registration fields." : lines.joined(separator: "\n")
    }
}
