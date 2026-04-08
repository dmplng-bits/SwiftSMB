//
//  MD4Tests.swift
//  SwiftSMB
//
//  Created by Preet Singh on 4/7/26.
//

import XCTest
@testable import SwiftSMB

final class MD4Tests: XCTestCase {

    // ── RFC 1320 §A.5 test vectors ──────────────────────────────────────
    // These are the official MD4 test vectors from the RFC.

    func testEmpty() {
        let hash = MD4.hash(data: Data())
        XCTAssertEqual(hash.hexDump, "31 d6 cf e0 d1 6a e9 31 b7 3c 59 d7 e0 c0 89 c0")
    }

    func testA() {
        let hash = MD4.hash(data: Data("a".utf8))
        XCTAssertEqual(hash.hexDump, "bd e5 2c b3 1d e3 3e 46 24 5e 05 fb db d6 fb 24")
    }

    func testABC() {
        let hash = MD4.hash(data: Data("abc".utf8))
        XCTAssertEqual(hash.hexDump, "a4 48 01 7a af 21 d8 52 5f c1 0a e8 7a a6 72 9d")
    }

    func testMessageDigest() {
        let hash = MD4.hash(data: Data("message digest".utf8))
        XCTAssertEqual(hash.hexDump, "d9 13 0a 81 64 54 9f e8 18 87 48 50 b8 9d 43 52")
    }

    func testAlphabet() {
        let hash = MD4.hash(data: Data("abcdefghijklmnopqrstuvwxyz".utf8))
        XCTAssertEqual(hash.hexDump, "d7 9e 1c 30 8a a5 bb cd ee a8 ed 63 df 41 2d a9")
    }

    func testAlphanumericMixed() {
        let hash = MD4.hash(data: Data("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".utf8))
        XCTAssertEqual(hash.hexDump, "04 3f 85 82 f2 41 db 35 1c e6 27 e1 53 e7 f0 e4")
    }

    func testNumericRepeated() {
        let hash = MD4.hash(data: Data("12345678901234567890123456789012345678901234567890123456789012345678901234567890".utf8))
        XCTAssertEqual(hash.hexDump, "e3 3b 4d dc 9c 38 f2 19 9c 3e 7b 16 4f cc 05 36")
    }

    // ── NTLMv2-relevant: UTF-16LE password hash ────────────────────────

    func testNTHashPassword() {
        // MD4(UTF-16LE("Password")) — the classic NT hash test.
        let utf16le = "Password".utf16leData
        let hash = MD4.hash(data: utf16le)
        XCTAssertEqual(hash.hexDump, "a4 f4 9c 40 65 10 bd ca b6 82 4e e7 c3 0f d8 52")
    }

    // ── Edge cases ──────────────────────────────────────────────────────

    func testExactlyOneBlock() {
        // 55 bytes + 1 byte padding + 8 byte length = exactly 64 bytes
        let data = Data(repeating: 0x41, count: 55)
        let hash = MD4.hash(data: data)
        XCTAssertEqual(hash.count, 16)
    }

    func testTwoBlockPadding() {
        // 56 bytes requires a second block for the length field
        let data = Data(repeating: 0x42, count: 56)
        let hash = MD4.hash(data: data)
        XCTAssertEqual(hash.count, 16)
    }

    func testLargeInput() {
        // 1 million 'a' characters — verifies multi-block processing
        let data = Data(repeating: 0x61, count: 1_000_000)
        let hash = MD4.hash(data: data)
        // Known MD4 value for 1 million 'a's
        XCTAssertEqual(hash.count, 16)
        // Just verify it doesn't crash and returns 16 bytes.
        // (The actual digest is not in RFC 1320 but is deterministic.)
    }
}
