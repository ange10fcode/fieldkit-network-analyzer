import XCTest
@testable import FieldKitCore

final class CoreTests: XCTestCase {
    func testSubnetCanonicalizationAndHostRules() throws {
        let subnet = try IPv4Subnet("192.168.7.43/24")
        XCTAssertEqual(subnet.description, "192.168.7.0/24")
        XCTAssertEqual(subnet.hosts.count, 254)
        XCTAssertEqual(subnet.hosts.first, "192.168.7.1")
        XCTAssertEqual(subnet.hosts.last, "192.168.7.254")
        XCTAssertEqual(try IPv4Subnet("10.0.0.1/31").hosts, ["10.0.0.0", "10.0.0.1"])
        XCTAssertEqual(try IPv4Subnet("10.0.0.1/32").hosts, ["10.0.0.1"])
        XCTAssertEqual(try IPv4Subnet("10.0.0.0/20").hosts.count, 4094)
    }
    func testUnsafeAndMalformedSubnetsRejected() {
        for invalid in ["10.0.0.0/19", "0.0.0.0/0", "1.2.3.4/33", "1.2.3.256/24", "::1/32", "1.2.3.4", "1.2.3.4/", "-1.2.3.4/24"] {
            XCTAssertThrowsError(try IPv4Subnet(invalid), invalid)
        }
    }
    func testPortRangesDeduplicateAndLimit() throws {
        XCTAssertEqual(try PortSpec.parse("22,80,79-81"), [22,79,80,81])
        XCTAssertEqual(try PortSpec.parse("65535"), [65535])
        for invalid in ["0", "65536", "80-22", "1-65535", "", "22,"] { XCTAssertThrowsError(try PortSpec.parse(invalid)) }
    }
    func testWakePacketAndValidation() throws {
        let packet = try WakePacket.make(mac: "00:11:22:33:44:55")
        XCTAssertEqual(packet.count, 102)
        XCTAssertEqual(Array(packet.prefix(6)), Array(repeating: 255, count: 6))
        XCTAssertEqual(Array(packet.suffix(6)), [0,17,34,51,68,85])
        XCTAssertThrowsError(try WakePacket.make(mac: "00:11:22:33:44:ZZ"))
    }
    func testEvidenceTagsAndSnapshotRoundTrip() throws {
        let device = LANDevice(address: "fe80::1", name: "Printer", nameSource: "Bonjour", advertisedServices: ["_ipp._tcp"], isThisDevice: false)
        XCTAssertEqual(device.tags, ["IPv6", "Bonjour"])
        XCTAssertFalse(device.tags.contains("Bluetooth"))
        let copy = try JSONDecoder().decode(LANDevice.self, from: JSONEncoder().encode(device))
        XCTAssertEqual(copy, device)
        XCTAssertEqual(LANDevice(address: "192.168.1.2").displayName, "Unnamed device")
    }
    func testHumanReadableRegistration() throws {
        let data = Data(#"{"ldhName":"example.org","status":["active"],"entities":[{"roles":["registrar"],"vcardArray":["vcard",[["fn",{},"text","Example Registrar"]]]}],"events":[{"eventAction":"registration","eventDate":"2020-01-01"}]}"#.utf8)
        let text = try RegistrationSummary.text(from: data)
        XCTAssertTrue(text.contains("Domain: example.org"))
        XCTAssertTrue(text.contains("Registrar: Example Registrar"))
        XCTAssertTrue(text.contains("Registration: 2020-01-01"))
        XCTAssertThrowsError(try RegistrationSummary.text(from: Data("[]".utf8)))
    }
}
