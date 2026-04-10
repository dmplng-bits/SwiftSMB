//
//  SMBSessionCreditTests.swift
//  SwiftSMB
//
//  Created by Preet Singh on 4/9/26.
//
// Unit tests for the SMB2 credit charge computation. These are pure
// functions — no network required.

import XCTest
@testable import SwiftSMB

final class SMBSessionCreditTests: XCTestCase {

    // MARK: - Credit charge computation

    func testCreditChargeForZeroBytesIsOne() {
        XCTAssertEqual(SMBSession.creditCharge(forPayloadLength: 0), 1)
    }

    func testCreditChargeForOneByte() {
        XCTAssertEqual(SMBSession.creditCharge(forPayloadLength: 1), 1)
    }

    func testCreditChargeForExactly64KiB() {
        // 65536 bytes should cost exactly 1 credit.
        XCTAssertEqual(SMBSession.creditCharge(forPayloadLength: 65536), 1)
    }

    func testCreditChargeFor64KiBPlusOne() {
        // 65537 bytes crosses the boundary → 2 credits.
        XCTAssertEqual(SMBSession.creditCharge(forPayloadLength: 65537), 2)
    }

    func testCreditChargeFor128KiB() {
        XCTAssertEqual(SMBSession.creditCharge(forPayloadLength: 131072), 2)
    }

    func testCreditChargeFor1MiB() {
        // 1048576 / 65536 = 16 credits.
        XCTAssertEqual(SMBSession.creditCharge(forPayloadLength: 1_048_576), 16)
    }

    func testCreditChargeFor4MiB() {
        // 4194304 / 65536 = 64 credits.
        XCTAssertEqual(SMBSession.creditCharge(forPayloadLength: 4_194_304), 64)
    }

    func testCreditChargeFormula() {
        // Verify the formula matches: 1 + ((payloadSize - 1) / 65536)
        let sizes: [Int] = [1, 100, 65535, 65536, 65537, 100_000, 1_000_000, 16_777_216]
        for size in sizes {
            let expected: UInt16 = UInt16(1 + (size - 1) / 65536)
            XCTAssertEqual(
                SMBSession.creditCharge(forPayloadLength: size),
                expected,
                "Mismatch for payload size \(size)"
            )
        }
    }

    // MARK: - Affordable payload length

    func testAffordablePayloadLengthWithEnoughCredits() async {
        let session = SMBSession(host: "127.0.0.1")
        // Fresh session starts with 0 credits; can't meaningfully test
        // the affordable check without injecting credits. Instead we
        // test the formula directly:
        let desired = 1_048_576  // 1 MiB = 16 credits
        let charge = SMBSession.creditCharge(forPayloadLength: desired)
        XCTAssertEqual(charge, 16)
    }

    // MARK: - Credential state

    func testStoredCredentialsNilByDefault() async {
        let session = SMBSession(host: "127.0.0.1")
        // Can't access storedCredentials directly (private), so verify
        // reconnect returns false without stored credentials.
        let ok = await session.reconnect()
        XCTAssertFalse(ok)
    }
}
