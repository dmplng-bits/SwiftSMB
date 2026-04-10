//
//  SMBTransportTests.swift
//  SwiftSMB
//
//  Created by Preet Singh on 4/8/26.
//
// Unit tests for the SMBTransport framing logic. We can't open a real
// socket in the test runner, so these tests focus on the pure parts:
// NetBIOS length encode/decode and endpoint configuration.

import XCTest
@testable import SwiftSMB

final class SMBTransportTests: XCTestCase {

    // MARK: - Endpoint

    func testEndpointDefaultsToPort445() {
        let ep = SMBTransport.Endpoint(host: "192.168.1.100")
        XCTAssertEqual(ep.host, "192.168.1.100")
        XCTAssertEqual(ep.port, 445)
    }

    func testEndpointEquality() {
        let a = SMBTransport.Endpoint(host: "10.0.0.1", port: 445)
        let b = SMBTransport.Endpoint(host: "10.0.0.1", port: 445)
        let c = SMBTransport.Endpoint(host: "10.0.0.2", port: 445)
        XCTAssertEqual(a, b)
        XCTAssertNotEqual(a, c)
    }

    // MARK: - NetBIOS framing

    func testEncodeLengthZero() {
        XCTAssertEqual(SMBTransport.encodeLength(0), [0x00, 0x00, 0x00, 0x00])
    }

    func testEncodeLengthSmall() {
        // 64 bytes → [0x00, 0x00, 0x00, 0x40]
        XCTAssertEqual(SMBTransport.encodeLength(64), [0x00, 0x00, 0x00, 0x40])
    }

    func testEncodeLengthMedium() {
        // 0x1234 = 4660 bytes → [0x00, 0x00, 0x12, 0x34]
        XCTAssertEqual(SMBTransport.encodeLength(0x1234), [0x00, 0x00, 0x12, 0x34])
    }

    func testEncodeLengthLarge() {
        // 0x00AB_CDEF → [0x00, 0xAB, 0xCD, 0xEF]
        XCTAssertEqual(SMBTransport.encodeLength(0x00AB_CDEF), [0x00, 0xAB, 0xCD, 0xEF])
    }

    func testEncodeLengthMax24Bit() {
        // 0xFFFFFF is the largest value NetBIOS framing can carry.
        XCTAssertEqual(SMBTransport.encodeLength(0x00FF_FFFF), [0x00, 0xFF, 0xFF, 0xFF])
    }

    func testDecodeLengthZero() {
        XCTAssertEqual(SMBTransport.decodeLength(Data([0x00, 0x00, 0x00, 0x00])), 0)
    }

    func testDecodeLengthSmall() {
        XCTAssertEqual(SMBTransport.decodeLength(Data([0x00, 0x00, 0x00, 0x40])), 64)
    }

    func testDecodeLengthMedium() {
        XCTAssertEqual(SMBTransport.decodeLength(Data([0x00, 0x00, 0x12, 0x34])), 0x1234)
    }

    func testDecodeLengthLarge() {
        XCTAssertEqual(SMBTransport.decodeLength(Data([0x00, 0xAB, 0xCD, 0xEF])), 0x00AB_CDEF)
    }

    func testDecodeLengthIgnoresTopByte() {
        // NetBIOS session type byte should be ignored when extracting length.
        let withType: Data = Data([0x85, 0x00, 0x12, 0x34])
        XCTAssertEqual(SMBTransport.decodeLength(withType), 0x1234)
    }

    // MARK: - Round-trip

    func testEncodeDecodeRoundTrip() {
        let sizes: [UInt32] = [0, 1, 17, 64, 256, 1024, 4096, 65535, 0x0FFFFF, 0x00FF_FFFF]
        for size in sizes {
            let encoded = SMBTransport.encodeLength(size)
            XCTAssertEqual(encoded.count, 4)
            let decoded = SMBTransport.decodeLength(Data(encoded))
            XCTAssertEqual(decoded, size, "Round-trip failed for size \(size)")
        }
    }

    // MARK: - Configuration

    func testMaxMessageSizeIsSixteenMebibytes() {
        XCTAssertEqual(SMBTransport.maxMessageSize, 16 * 1024 * 1024)
    }

    func testDefaultTimeouts() {
        let t = SMBTransport.Timeouts()
        XCTAssertEqual(t.connect, 10)
        XCTAssertEqual(t.send,    30)
        XCTAssertEqual(t.receive, 30)
    }

    func testCustomTimeouts() {
        let t = SMBTransport.Timeouts(connect: 5, send: 15, receive: 20)
        XCTAssertEqual(t.connect, 5)
        XCTAssertEqual(t.send,    15)
        XCTAssertEqual(t.receive, 20)
    }
}
