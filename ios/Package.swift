// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "FieldKitCore",
    platforms: [.iOS(.v16), .macOS(.v13)],
    products: [.library(name: "FieldKitCore", targets: ["FieldKitCore"])],
    targets: [
        .target(name: "FieldKitCore"),
        .testTarget(name: "FieldKitCoreTests", dependencies: ["FieldKitCore"])
    ]
)
