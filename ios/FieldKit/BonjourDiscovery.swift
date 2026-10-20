import Foundation

@MainActor
final class BonjourDiscovery: NSObject, NetServiceBrowserDelegate, NetServiceDelegate {
    private var browsers: [NetServiceBrowser] = []
    private var services: [String: NetService] = [:]
    private var expiry: Task<Void, Never>?
    var found: ((String, String, String) -> Void)?
    var status: ((String) -> Void)?
    static let types = ["_http._tcp.", "_https._tcp.", "_ssh._tcp.", "_ipp._tcp.", "_smb._tcp.", "_workstation._tcp.", "_googlecast._tcp.", "_raop._tcp."]
    func start() {
        stop()
        for type in Self.types {
            let browser = NetServiceBrowser(); browser.delegate = self
            browsers.append(browser); browser.searchForServices(ofType: type, inDomain: "local.")
        }
        status?("Listening for published Bonjour names…")
        expiry = Task { [weak self] in
            try? await Task.sleep(nanoseconds: 8_000_000_000)
            guard !Task.isCancelled else { return }
            self?.stop()
        }
    }
    func stop() {
        expiry?.cancel(); expiry = nil
        browsers.forEach { $0.stop() }; browsers.removeAll()
        services.values.forEach { $0.stop() }; services.removeAll()
    }
    func netServiceBrowser(_ browser: NetServiceBrowser, didFind service: NetService, moreComing: Bool) {
        let key = service.type + service.domain + service.name
        guard services[key] == nil, services.count < 256 else { return }
        services[key] = service; service.delegate = self; service.resolve(withTimeout: 4)
    }
    func netServiceDidResolveAddress(_ sender: NetService) {
        guard let addresses = sender.addresses else { return }
        let evidence = "\(sender.type) port \(sender.port) advertised"
        for data in addresses {
            if let address = InterfaceInventory.numericAddress(data) { found?(address, sender.name, evidence) }
        }
    }
    func netServiceBrowser(_ browser: NetServiceBrowser, didNotSearch errorDict: [String : NSNumber]) {
        status?("Bonjour unavailable. Allow FieldKit in Settings → Privacy & Security → Local Network. \(errorDict)")
    }
}
