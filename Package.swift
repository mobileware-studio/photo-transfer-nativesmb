// swift-tools-version: 6.0
import PackageDescription
let package = Package(
    name: "NativeSMB", platforms: [.iOS(.v16), .macOS(.v13)],
    products: [.library(name: "NativeSMB", type: .dynamic, targets: ["NativeSMB"])],
    targets: [
        .target(name: "CSMB", path: "Sources/CSMB", sources: ["lib"], publicHeadersPath: "include",
                cSettings: [.headerSearchPath("include/apple"), .headerSearchPath("include/smb2"),
                            .headerSearchPath("lib"), .define("_U_", to: "__attribute__((unused))"), .define("HAVE_CONFIG_H", to: "1")],
                linkerSettings: [.linkedLibrary("resolv")]),
        .target(name: "NativeSMB", dependencies: ["CSMB"]),
        // `swift test` on macOS. Real-DNS checks opt in with NATIVESMB_REAL_DNS=1.
        .testTarget(name: "NativeSMBTests", dependencies: ["NativeSMB", "CSMB"])
    ], swiftLanguageModes: [.v5]
)
