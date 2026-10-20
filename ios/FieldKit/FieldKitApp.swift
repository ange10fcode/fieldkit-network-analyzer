import SwiftUI

@main
@MainActor
struct FieldKitApp: App {
    @StateObject private var model = AppModel()
    @StateObject private var bluetooth = BluetoothFinder()
    @StateObject private var precision = PrecisionFinder()
    @Environment(\.scenePhase) private var phase
    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(model).environmentObject(bluetooth).environmentObject(precision)
                .preferredColorScheme(model.colorScheme)
                .tint(.teal)
                .onChange(of: phase) { phase in
                    if phase == .background { model.background(); bluetooth.stop(); if precision.active { precision.stop() } }
                    else if phase == .active { model.refresh() }
                }
        }
    }
}
