import Foundation
import CoreBluetooth
import Combine

struct BluetoothObservation: Identifiable, Codable {
    let id: UUID
    var name: String
    var rssi: Int
    var seen: Date
    var history: [SignalPoint]
}

final class BluetoothFinder: NSObject, ObservableObject, CBCentralManagerDelegate {
    @Published var devices: [BluetoothObservation] = []
    @Published var selected: UUID?
    @Published var scanning = false
    @Published var status = "Start a scan to find Bluetooth LE advertisers."
    @Published var baseline: Int?
    private var central: CBCentralManager?
    private var timeout: DispatchWorkItem?
    private var requested = false
    private var lastSave = Date.distantPast
    private let file = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent("FieldKit/bluetooth.json")
    private struct Saved: Codable { var devices: [BluetoothObservation]; var selected: UUID?; var baseline: Int? }
    override init() {
        super.init()
        if let data = try? Data(contentsOf: file), let saved = try? JSONDecoder().decode(Saved.self, from: data) {
            devices = saved.devices; selected = saved.selected; baseline = saved.baseline
            if !devices.isEmpty { status = "Saved observations. Start scanning for live signal updates." }
        }
    }
    var target: BluetoothObservation? { devices.first { $0.id == selected } }
    func select(_ device: BluetoothObservation) { selected = device.id; baseline = device.rssi; save() }
    func start() {
        requested = true
        if central == nil { central = CBCentralManager(delegate: self, queue: .main) }
        else { beginIfReady() }
    }
    private func beginIfReady() {
        guard requested, let central else { return }
        guard central.state == .poweredOn else { return }
        central.scanForPeripherals(withServices: nil, options: [CBCentralManagerScanOptionAllowDuplicatesKey: true])
        scanning = true; status = "Listening for Bluetooth LE advertisements…"
        timeout?.cancel()
        let work = DispatchWorkItem { [weak self] in self?.stop() }
        timeout = work; DispatchQueue.main.asyncAfter(deadline: .now() + 30, execute: work)
    }
    func stop() {
        requested = false; central?.stopScan(); timeout?.cancel(); timeout = nil
        scanning = false; status = devices.isEmpty ? "No advertisers found. A device must actively advertise Bluetooth LE to appear." : "Scan stopped. Observations remain saved with their original times."
        save()
    }
    func resetBaseline() { baseline = target?.rssi; save() }
    func clear() { stop(); devices = []; selected = nil; baseline = nil; save() }
    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        switch central.state {
        case .poweredOn: beginIfReady()
        case .unauthorized: scanning = false; status = "Bluetooth permission denied. Enable it for FieldKit in Settings."
        case .unsupported: scanning = false; status = "Bluetooth LE scanning is unsupported on this device."
        case .poweredOff: scanning = false; status = "Turn on Bluetooth to scan."
        default: scanning = false; status = "Bluetooth is starting."
        }
    }
    func centralManager(_ central: CBCentralManager, didDiscover peripheral: CBPeripheral, advertisementData: [String : Any], rssi RSSI: NSNumber) {
        let rssi = RSSI.intValue
        guard scanning, (-127 ... -1).contains(rssi) else { return }
        let name = (advertisementData[CBAdvertisementDataLocalNameKey] as? String) ?? peripheral.name ?? "Unnamed Bluetooth device"
        if let index = devices.firstIndex(where: { $0.id == peripheral.identifier }) {
            devices[index].name = name; devices[index].rssi = rssi; devices[index].seen = Date()
            devices[index].history.append(SignalPoint(value: Double(rssi)))
            if devices[index].history.count > 60 { devices[index].history.removeFirst(devices[index].history.count - 60) }
        } else if devices.count < 256 {
            devices.append(BluetoothObservation(id: peripheral.identifier, name: name, rssi: rssi, seen: Date(), history: [SignalPoint(value: Double(rssi))]))
        }
        // Coalesce radio bursts. stop/on-background also synchronously saves the latest observation.
        if Date().timeIntervalSince(lastSave) >= 0.75 { save() }
    }
    private func save() {
        lastSave = Date()
        guard let data = try? JSONEncoder().encode(Saved(devices: devices, selected: selected, baseline: baseline)) else { return }
        try? FileManager.default.createDirectory(at: file.deletingLastPathComponent(), withIntermediateDirectories: true)
        try? data.write(to: file, options: .atomic)
    }
}
