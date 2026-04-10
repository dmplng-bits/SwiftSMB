//
//  SMBDiscoveryTests.swift
//  SwiftSMB
//
//  Created by Preet Singh on 4/9/26.
//
// Unit tests for SMBDiscovery and SMBShareInfo. The Bonjour browsing
// itself requires a live network, so these tests focus on the value
// types: SMBServer, SMBShareInfo, and their properties.

import XCTest
@testable import SwiftSMB

final class SMBDiscoveryTests: XCTestCase {

    // MARK: - SMBServer

    func testSMBServerDefaultPort() {
        let s = SMBServer(name: "NAS", host: "192.168.1.100")
        XCTAssertEqual(s.port, 445)
    }

    func testSMBServerEquality() {
        let a = SMBServer(name: "NAS", host: "10.0.0.1")
        let b = SMBServer(name: "NAS", host: "10.0.0.1")
        let c = SMBServer(name: "Other", host: "10.0.0.2")
        XCTAssertEqual(a, b)
        XCTAssertNotEqual(a, c)
    }

    func testSMBServerIdentity() {
        let s = SMBServer(name: "NAS", host: "10.0.0.1", port: 445)
        XCTAssertEqual(s.id, "10.0.0.1:445")
    }

    // MARK: - SMBShareInfo

    func testDiskShareIsDisk() {
        let s = SMBShareInfo(name: "Videos", type: 0x0000_0000, comment: "Media")
        XCTAssertTrue(s.isDisk)
        XCTAssertFalse(s.isSpecial)
    }

    func testIPCShareIsNotDisk() {
        // IPC shares have type = 0x0000_0003 (pipe) usually with special bit.
        let s = SMBShareInfo(name: "IPC$", type: 0x8000_0003, comment: "IPC")
        XCTAssertFalse(s.isDisk)
        XCTAssertTrue(s.isSpecial)
    }

    func testAdminShareIsSpecial() {
        // ADMIN$ is a disk share (type 0) with the special bit set.
        let s = SMBShareInfo(name: "ADMIN$", type: 0x8000_0000, comment: "Admin")
        XCTAssertTrue(s.isDisk)
        XCTAssertTrue(s.isSpecial)
    }

    func testPrinterShare() {
        let s = SMBShareInfo(name: "Printer", type: 0x0000_0001, comment: "")
        XCTAssertFalse(s.isDisk)
        XCTAssertFalse(s.isSpecial)
    }

    func testShareInfoIdentity() {
        let s = SMBShareInfo(name: "Movies", type: 0, comment: "")
        XCTAssertEqual(s.id, "Movies")
    }

    // MARK: - SMBDiscovery state

    func testFreshDiscoveryHasNoServers() async {
        let d = SMBDiscovery()
        let servers = await d.servers
        XCTAssertTrue(servers.isEmpty)
    }
}
