// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "Cyphera",
    platforms: [
        .macOS(.v10_15),
        .iOS(.v13),
        .tvOS(.v13),
        .watchOS(.v6)
    ],
    products: [
        .library(
            name: "Cyphera",
            targets: ["Cyphera"]),
    ],
    dependencies: [
        .package(url: "https://github.com/attaswift/BigInt.git", "5.0.0"..<"6.0.0"),
        // CryptoSwift only needed on non-Apple platforms
        .package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", "1.8.0"..<"2.0.0"),
    ],
    targets: [
        .target(
            name: "Cyphera",
            dependencies: [
                .product(name: "BigInt", package: "BigInt"),
                .product(name: "CryptoSwift", package: "CryptoSwift",
                         condition: .when(platforms: [.linux, .windows, .android, .wasi, .openbsd])),
            ]),
        .testTarget(
            name: "CypheraTests",
            dependencies: ["Cyphera"]),
    ]
)
