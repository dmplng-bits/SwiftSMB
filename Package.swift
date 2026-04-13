// swift-tools-version: 5.9
//
//  Package.swift
//  SwiftSMB
//
//  Created by Preet Singh on 4/7/26.
//

import PackageDescription

let package = Package(
    name: "SwiftSMB",
    platforms: [
        .tvOS(.v17),
        .iOS(.v17),
        .macOS(.v14),
    ],
    products: [
        .library(
            name: "SwiftSMB",
            targets: ["SwiftSMB"]
        ),
    ],
    targets: [
        .target(
            name: "SwiftSMB",
            path: "Sources/SwiftSMB"
        ),
        .testTarget(
            name: "SwiftSMBTests",
            dependencies: ["SwiftSMB"],
            path: "Tests/SwiftSMBTests"
        ),
    ]
)
