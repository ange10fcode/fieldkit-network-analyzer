import Foundation
import NearbyInteraction
import MultipeerConnectivity
import CryptoKit
import simd
import UIKit
import Combine

/// Foreground-only ranging between two FieldKit iOS installations. No commercial tag protocol.
final class PrecisionFinder: NSObject, ObservableObject, NISessionDelegate, MCSessionDelegate, MCNearbyServiceAdvertiserDelegate, MCNearbyServiceBrowserDelegate {
    @Published var status = "Check this phone before pairing."
    @Published var supported = false
    @Published var directionSupported = false
    @Published var active = false
    @Published var hosting = false
    @Published var pairingCode = ""
    @Published var peers: [MCPeerID] = []
    @Published var incomingName: String?
    @Published var distance: Float?
    @Published var azimuth: Double?
    @Published var elevation: Double?
    @Published var measuredAt: Date?
    private var localPeer = MCPeerID(displayName: "FieldKit iPhone")
    private var channel: MCSession?
    private var advertiser: MCNearbyServiceAdvertiser?
    private var browser: MCNearbyServiceBrowser?
    private var ranging: NISession?
    private var peerToken: NIDiscoveryToken?
    private var secret: Data?
    private var challenge: Data?
    private var authorized = false
    private var invitation: ((Bool, MCSession?) -> Void)?
    private var attempts = 0
    private static let service = "fieldkit-ni"
    var localDisplayName: String { localPeer.displayName }

    override init() { super.init(); checkSupport() }

    func checkSupport() {
        supported = NISession.deviceCapabilities.supportsPreciseDistanceMeasurement
        directionSupported = NISession.deviceCapabilities.supportsDirectionMeasurement
        status = supported ? (directionSupported ? "Precise distance and direction are supported." : "Precise distance is supported; direction is unavailable on this phone.") : "Unsupported on this phone. Nearby Interaction cannot measure precise distance here."
    }

    func host() {
        stop(); checkSupport(); guard supported else { return }
        let key = SymmetricKey(size: .bits128)
        let bytes = key.withUnsafeBytes { Data($0) }
        secret = bytes
        pairingCode = bytes.map { String(format: "%02x", $0) }.joined()
        prepare(); hosting = true
        let advertiser = MCNearbyServiceAdvertiser(peer: localPeer, discoveryInfo: ["v":"1"], serviceType: Self.service)
        self.advertiser = advertiser; advertiser.delegate = self; advertiser.startAdvertisingPeer()
        status = "Share this private pairing code with the other FieldKit iPhone. Keep both apps open."
    }

    func browse(code: String) {
        stop(); checkSupport(); guard supported else { return }
        let compact = code.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard compact.count == 32, compact.allSatisfy({ $0.isHexDigit }) else { status = "Paste the complete 32-character code shown on the other phone."; return }
        var bytes = Data()
        for offset in stride(from: 0, to: 32, by: 2) {
            let start = compact.index(compact.startIndex, offsetBy: offset)
            guard let byte = UInt8(compact[start..<compact.index(start, offsetBy: 2)], radix: 16) else { return }
            bytes.append(byte)
        }
        secret = bytes; prepare()
        let browser = MCNearbyServiceBrowser(peer: localPeer, serviceType: Self.service)
        self.browser = browser; browser.delegate = self; browser.startBrowsingForPeers()
        status = "Choose the other FieldKit iPhone below."
    }

    private func prepare() {
        localPeer = MCPeerID(displayName: "FieldKit " + String(UUID().uuidString.prefix(4)))
        let channel = MCSession(peer: localPeer, securityIdentity: nil, encryptionPreference: .required)
        self.channel = channel; channel.delegate = self
        let session = NISession(); session.delegate = self; session.delegateQueue = .main
        ranging = session; active = true
    }

    func connect(_ peer: MCPeerID) {
        guard let channel, channel.connectedPeers.isEmpty else { return }
        browser?.invitePeer(peer, to: channel, withContext: Data("FieldKit1".utf8), timeout: 20)
        status = "Waiting for approval on \(peer.displayName)…"
    }

    func approve(_ accept: Bool) {
        invitation?(accept, accept ? channel : nil)
        invitation = nil; incomingName = nil
        status = accept ? "Connecting through an encrypted local session…" : "Invitation declined."
    }

    func stop() {
        invitation?(false, nil); invitation = nil; incomingName = nil
        advertiser?.stopAdvertisingPeer(); advertiser = nil
        browser?.stopBrowsingForPeers(); browser = nil
        channel?.disconnect(); channel = nil
        ranging?.invalidate(); ranging = nil
        peerToken = nil; secret = nil; challenge = nil; authorized = false; attempts = 0
        active = false; hosting = false; peers = []
        distance = nil; azimuth = nil; elevation = nil; measuredAt = nil; pairingCode = ""
        status = "Stopped. Start a new session to find another compatible iPhone."
    }

    private struct Message: Codable { let kind: String; let payload: Data }
    private func send(_ kind: String, _ payload: Data, to peer: MCPeerID) {
        guard let channel, let data = try? JSONEncoder().encode(Message(kind: kind, payload: payload)) else { return }
        do { try channel.send(data, toPeers: [peer], with: .reliable) }
        catch { status = "Connection failed: \(error.localizedDescription)" }
    }
    private func sendToken(to peer: MCPeerID) {
        guard authorized, let token = ranging?.discoveryToken,
              let data = try? NSKeyedArchiver.archivedData(withRootObject: token, requiringSecureCoding: true) else { return }
        send("token", data, to: peer)
        status = "Paired. Keep the phones nearby, upright and unobstructed."
        advertiser?.stopAdvertisingPeer(); browser?.stopBrowsingForPeers()
    }

    func session(_ session: MCSession, peer peerID: MCPeerID, didChange state: MCSessionState) {
        DispatchQueue.main.async { [weak self] in
            guard let self, self.channel === session else { return }
            if state == .connected {
                guard session.connectedPeers.count == 1 else { self.stop(); return }
                let key = SymmetricKey(size: .bits256)
                let nonce = key.withUnsafeBytes { Data($0) }
                self.challenge = nonce
                self.send("challenge", nonce, to: peerID)
                self.status = "Verifying the private pairing code…"
            } else if state == .notConnected {
                self.distance = nil; self.azimuth = nil; self.elevation = nil; self.measuredAt = nil
                self.authorized = false; self.ranging?.pause()
                self.status = "Peer disconnected. Start a new session on both phones."
            }
        }
    }

    func session(_ session: MCSession, didReceive data: Data, fromPeer peerID: MCPeerID) {
        guard data.count <= 65536 else { return }
        DispatchQueue.main.async { [weak self] in
            guard let self, self.channel === session, let secret = self.secret,
                  let message = try? JSONDecoder().decode(Message.self, from: data) else { return }
            let key = SymmetricKey(data: secret)
            switch message.kind {
            case "challenge":
                guard message.payload.count == 32, self.attempts < 3 else { return }
                self.attempts += 1
                let proof = Data(HMAC<SHA256>.authenticationCode(for: message.payload, using: key))
                self.send("proof", proof, to: peerID)
            case "proof":
                guard let challenge = self.challenge,
                      HMAC<SHA256>.isValidAuthenticationCode(message.payload, authenticating: challenge, using: key) else {
                    self.stop(); self.status = "Pairing code did not match. Create a new code and try again."; return
                }
                self.challenge = nil; self.authorized = true; self.sendToken(to: peerID)
            case "token":
                guard self.authorized,
                      let token = try? NSKeyedUnarchiver.unarchivedObject(ofClass: NIDiscoveryToken.self, from: message.payload) else { return }
                self.peerToken = token
                self.ranging?.run(NINearbyPeerConfiguration(peerToken: token))
                self.status = "Measuring… hold the phone upright with its rear camera facing the search area."
            default: break
            }
        }
    }

    func session(_ session: NISession, didUpdate nearbyObjects: [NINearbyObject]) {
        guard session === ranging, let peerToken, let object = nearbyObjects.first(where: { $0.discoveryToken == peerToken }) else { return }
        distance = object.distance
        if let vector = object.direction {
            azimuth = atan2(Double(vector.x), Double(-vector.z))
            elevation = atan2(Double(vector.y), hypot(Double(vector.x), Double(vector.z)))
        } else { azimuth = nil; elevation = nil }
        measuredAt = Date()
        status = object.distance == nil ? "Searching. Move closer and keep the phones unobstructed." : (object.direction == nil ? "Distance measured. Direction is currently unavailable." : "Live measurement")
    }
    func session(_ session: NISession, didRemove nearbyObjects: [NINearbyObject], reason: NINearbyObject.RemovalReason) {
        guard session === ranging else { return }
        distance = nil; azimuth = nil; elevation = nil; measuredAt = nil
        if reason == .timeout, let peerToken { session.run(NINearbyPeerConfiguration(peerToken: peerToken)); status = "Peer out of range. Move closer." }
        else { status = "Peer ended ranging. Start a new session on both phones." }
    }
    func sessionWasSuspended(_ session: NISession) {
        guard session === ranging else { return }
        distance = nil; azimuth = nil; elevation = nil; measuredAt = nil; status = "Ranging suspended. Return to FieldKit on both phones."
    }
    func sessionSuspensionEnded(_ session: NISession) {
        guard session === ranging else { return }
        if let peerToken { session.run(NINearbyPeerConfiguration(peerToken: peerToken)) }
    }
    func session(_ session: NISession, didInvalidateWith error: Error) {
        guard session === ranging else { return }
        distance = nil; azimuth = nil; elevation = nil; measuredAt = nil
        status = "Ranging ended: \(error.localizedDescription). Check Nearby Interaction permission in Settings."
    }

    func advertiser(_ advertiser: MCNearbyServiceAdvertiser, didReceiveInvitationFromPeer peerID: MCPeerID, withContext context: Data?, invitationHandler: @escaping (Bool, MCSession?) -> Void) {
        DispatchQueue.main.async { [weak self] in
            guard let self, self.hosting, self.invitation == nil, self.channel?.connectedPeers.isEmpty == true else { invitationHandler(false, nil); return }
            self.invitation = invitationHandler; self.incomingName = peerID.displayName
        }
    }
    func advertiser(_ advertiser: MCNearbyServiceAdvertiser, didNotStartAdvertisingPeer error: Error) { DispatchQueue.main.async { self.status = "Cannot advertise: \(error.localizedDescription). Check Local Network permission." } }
    func browser(_ browser: MCNearbyServiceBrowser, foundPeer peerID: MCPeerID, withDiscoveryInfo info: [String : String]?) { DispatchQueue.main.async { if !self.peers.contains(peerID) { self.peers.append(peerID) } } }
    func browser(_ browser: MCNearbyServiceBrowser, lostPeer peerID: MCPeerID) { DispatchQueue.main.async { self.peers.removeAll { $0 == peerID } } }
    func browser(_ browser: MCNearbyServiceBrowser, didNotStartBrowsingForPeers error: Error) { DispatchQueue.main.async { self.status = "Cannot discover peers: \(error.localizedDescription). Check Local Network permission." } }
    func session(_ session: MCSession, didReceive stream: InputStream, withName streamName: String, fromPeer peerID: MCPeerID) {}
    func session(_ session: MCSession, didStartReceivingResourceWithName resourceName: String, fromPeer peerID: MCPeerID, with progress: Progress) {}
    func session(_ session: MCSession, didFinishReceivingResourceWithName resourceName: String, fromPeer peerID: MCPeerID, at localURL: URL?, withError error: Error?) {}
}
