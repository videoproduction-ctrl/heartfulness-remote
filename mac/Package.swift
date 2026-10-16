// swift-tools-version:5.10
// Heartfulness Remote — Mac host app.
//
//   HRCore              Foundation-only protocol/model logic (unit-tested, also builds on Linux)
//   HeartfulnessRemote  the menu-bar app (SwiftUI + AppKit, macOS 14+)
//   HRCoreTests         XCTest suite for HRCore
//
// Build the app bundle with scripts/build-mac.sh; run tests with `swift test`.
import PackageDescription

let package = Package(
    name: "HeartfulnessRemote",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "HRCore", targets: ["HRCore"]),
        .executable(name: "HeartfulnessRemote", targets: ["HeartfulnessRemote"]),
    ],
    targets: [
        .target(
            name: "HRCore",
            path: "Sources/HRCore"
        ),
        .executableTarget(
            name: "HeartfulnessRemote",
            dependencies: ["HRCore"],
            path: "Sources/HeartfulnessRemote"
        ),
        .testTarget(
            name: "HRCoreTests",
            dependencies: ["HRCore"],
            path: "Tests/HRCoreTests"
        ),
    ],
    swiftLanguageVersions: [.v5]
)
