//
//  ByteBufferTests.swift
//  SwiftSMB
//
//  Created by Preet Singh on 4/7/26.
//
// Tests for ByteWriter and ByteReader.
// Run with:  swift test

import XCTest
@testable import SwiftSMB

final class ByteBufferTests: XCTestCase {

    // MARK: - ByteWriter

    func test_writer_uint8() {
        var w = ByteWriter()
        w.uint8(0xFF)
        XCTAssertEqual(w.data, Data([0xFF]))
    }

    func test_writer_uint16le() {
        var w = ByteWriter()
        w.uint16le(0x1234)
        // Little-endian: low byte first
        XCTAssertEqual(w.data, Data([0x34, 0x12]))
    }

    func test_writer_uint32le() {
        var w = ByteWriter()
        w.uint32le(0xDEADBEEF)
        XCTAssertEqual(w.data, Data([0xEF, 0xBE, 0xAD, 0xDE]))
    }

    func test_writer_uint64le() {
        var w = ByteWriter()
        w.uint64le(0x0102030405060708)
        XCTAssertEqual(w.data, Data([0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]))
    }

    func test_writer_zeros() {
        var w = ByteWriter()
        w.zeros(4)
        XCTAssertEqual(w.data, Data(count: 4))
    }

    func test_writer_utf16le() {
        var w = ByteWriter()
        w.utf16le("AB")
        // 'A' = 0x41 0x00,  'B' = 0x42 0x00
        XCTAssertEqual(w.data, Data([0x41, 0x00, 0x42, 0x00]))
    }

    func test_writer_chaining() {
        var w = ByteWriter()
        w.uint8(0x01).uint16le(0x0203).uint32le(0x04050607)
        XCTAssertEqual(w.data.count, 1 + 2 + 4)
    }

    // MARK: - ByteReader sequential

    func test_reader_uint8() throws {
        var r = ByteReader(Data([0xAB]))
        XCTAssertEqual(try r.uint8(), 0xAB)
        XCTAssertTrue(r.atEnd)
    }

    func test_reader_uint16le() throws {
        var r = ByteReader(Data([0x34, 0x12]))
        XCTAssertEqual(try r.uint16le(), 0x1234)
    }

    func test_reader_uint32le() throws {
        var r = ByteReader(Data([0xEF, 0xBE, 0xAD, 0xDE]))
        XCTAssertEqual(try r.uint32le(), 0xDEADBEEF)
    }

    func test_reader_uint64le() throws {
        var r = ByteReader(Data([0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]))
        XCTAssertEqual(try r.uint64le(), 0x0102030405060708)
    }

    func test_reader_bytes() throws {
        var r = ByteReader(Data([0x01, 0x02, 0x03, 0x04]))
        let chunk = try r.bytes(2)
        XCTAssertEqual(chunk, Data([0x01, 0x02]))
        XCTAssertEqual(try r.bytes(2), Data([0x03, 0x04]))
        XCTAssertTrue(r.atEnd)
    }

    func test_reader_skip() throws {
        var r = ByteReader(Data([0xAA, 0xBB, 0xCC]))
        try r.skip(2)
        XCTAssertEqual(try r.uint8(), 0xCC)
    }

    func test_reader_rest() throws {
        var r = ByteReader(Data([0x01, 0x02, 0x03]))
        try r.skip(1)
        let rest = r.rest()
        XCTAssertEqual(rest, Data([0x02, 0x03]))
        XCTAssertTrue(r.atEnd)
    }

    func test_reader_truncated_throws() {
        var r = ByteReader(Data([0x01]))
        XCTAssertThrowsError(try r.uint32le()) { err in
            XCTAssertEqual(err as? SMBError, SMBError.truncatedPacket)
        }
    }

    // MARK: - ByteReader random-access

    func test_reader_randomAccess_uint16le() {
        let r = ByteReader(Data([0x00, 0x00, 0x34, 0x12]))
        XCTAssertEqual(r.uint16le(at: 2), 0x1234)
    }

    func test_reader_randomAccess_uint32le() {
        let r = ByteReader(Data([0x00, 0xEF, 0xBE, 0xAD, 0xDE]))
        XCTAssertEqual(r.uint32le(at: 1), 0xDEADBEEF)
    }

    func test_reader_subdata() {
        let r = ByteReader(Data([0x01, 0x02, 0x03, 0x04, 0x05]))
        XCTAssertEqual(r.subdata(at: 1, length: 3), Data([0x02, 0x03, 0x04]))
    }

    // MARK: - Round-trip (write then read back)

    func test_roundtrip() throws {
        var w = ByteWriter()
        w.uint8(0xFE)
        w.uint16le(0x1234)
        w.uint32le(0xDEADBEEF)
        w.uint64le(0xCAFEBABEDEADC0DE)
        w.utf16le("Hi")
        w.zeros(3)

        var r = ByteReader(w.data)
        XCTAssertEqual(try r.uint8(),    0xFE)
        XCTAssertEqual(try r.uint16le(), 0x1234)
        XCTAssertEqual(try r.uint32le(), 0xDEADBEEF)
        XCTAssertEqual(try r.uint64le(), 0xCAFEBABEDEADC0DE)
        XCTAssertEqual(try r.bytes(4),   Data([0x48,0x00,0x69,0x00]))  // "Hi" UTF-16LE
        XCTAssertEqual(try r.bytes(3),   Data(count: 3))
        XCTAssertTrue(r.atEnd)
    }

    // MARK: - String ↔ UTF-16LE

    func test_utf16leData() {
        XCTAssertEqual("A".utf16leData, Data([0x41, 0x00]))
        XCTAssertEqual("AB".utf16leData, Data([0x41, 0x00, 0x42, 0x00]))
        XCTAssertEqual("".utf16leData, Data())
    }

    func test_utf16leString_roundtrip() {
        let original = "Hello, 世界"
        XCTAssertEqual(original.utf16leData.utf16leString, original)
    }

    // MARK: - Hex dump

    func test_hexDump() {
        XCTAssertEqual(Data([0xFE, 0x53, 0x4D, 0x42]).hexDump, "fe 53 4d 42")
    }
}

// MARK: - SMBError equatable for XCTest

extension SMBError: Equatable {
    public static func == (lhs: SMBError, rhs: SMBError) -> Bool {
        lhs.errorDescription == rhs.errorDescription
    }
}
