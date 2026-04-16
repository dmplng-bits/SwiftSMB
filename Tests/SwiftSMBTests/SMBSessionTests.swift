//
//  SMBSessionTests.swift
//  SwiftSMB
//
//  Created by Preet Singh on 4/8/26.
//
// Unit tests for SMBSession. Since Session requires a live SMB server
// we can't reach from the test runner, these tests focus on:
//   * Credential value semantics
//   * The Negotiated info type
//   * Initial state invariants

import XCTest
@testable import SwiftSMB

final class SMBSessionTests: XCTestCase {

    // MARK: - Credentials

    func testCredentialsDefaultDomainIsEmpty() {
        let c = SMBCredentials(user: "alice", password: "hunter2")
        XCTAssertEqual(c.user, "alice")
        XCTAssertEqual(c.password, "hunter2")
        XCTAssertEqual(c.domain, "")
    }

    func testCredentialsExplicitDomain() {
        let c = SMBCredentials(user: "bob", password: "pw", domain: "WORKGROUP")
        XCTAssertEqual(c.domain, "WORKGROUP")
    }

    func testGuestCredentialsAreEmpty() {
        XCTAssertEqual(SMBCredentials.guest.user, "")
        XCTAssertEqual(SMBCredentials.guest.password, "")
        XCTAssertEqual(SMBCredentials.guest.domain, "")
    }

    // MARK: - Initial state

    func testFreshSessionStartsUnauthenticated() async {
        let session = SMBSession(host: "127.0.0.1")
        let isAuth = await session.isAuthenticated
        let isTree = await session.isConnectedToTree
        let mid    = await session.currentMessageId
        let sid    = await session.currentSessionId
        let tid    = await session.currentTreeId
        XCTAssertFalse(isAuth)
        XCTAssertFalse(isTree)
        XCTAssertEqual(mid, 0)
        XCTAssertEqual(sid, 0)
        XCTAssertEqual(tid, 0)
    }

    func testFreshSessionHasNoNegotiatedInfo() async {
        let session = SMBSession(host: "127.0.0.1")
        let info = await session.negotiated
        XCTAssertNil(info)
    }

    // MARK: - Negotiated info

    func testNegotiatedInfoHoldsExpectedFields() {
        let info = SMBSession.Negotiated(
            dialect:         SMB2Dialect.smb302,
            maxReadSize:     1 << 20,
            maxWriteSize:    1 << 20,
            maxTransactSize: 1 << 20,
            serverGuid:      Data(repeating: 0xAB, count: 16),
            securityBuffer:  Data([0xDE, 0xAD, 0xBE, 0xEF]),
            securityMode:    SMB2SecurityMode.signingEnabled,
            chosenCipher:    SMB2Cipher.aes128gcm
        )
        XCTAssertEqual(info.dialect, SMB2Dialect.smb302)
        XCTAssertEqual(info.maxReadSize, 1_048_576)
        XCTAssertEqual(info.maxWriteSize, 1_048_576)
        XCTAssertEqual(info.maxTransactSize, 1_048_576)
        XCTAssertEqual(info.serverGuid.count, 16)
        XCTAssertEqual(info.securityBuffer, Data([0xDE, 0xAD, 0xBE, 0xEF]))
        XCTAssertEqual(info.securityMode, SMB2SecurityMode.signingEnabled)
        XCTAssertEqual(info.chosenCipher, SMB2Cipher.aes128gcm)
    }

    // MARK: - Error paths

    func testAuthenticateBeforeNegotiateThrows() async {
        let session = SMBSession(host: "127.0.0.1")
        do {
            try await session.authenticate(SMBCredentials.guest)
            XCTFail("Expected authenticate() to throw before negotiate()")
        } catch let err as SMBError {
            switch err {
            case .negotiationFailed: break  // expected
            default:
                XCTFail("Expected .negotiationFailed, got \(err)")
            }
        } catch {
            XCTFail("Unexpected error type: \(error)")
        }
    }

    func testTreeConnectBeforeAuthenticateThrows() async {
        let session = SMBSession(host: "127.0.0.1")
        do {
            try await session.treeConnect("\\\\server\\share")
            XCTFail("Expected treeConnect() to throw before authenticate()")
        } catch let err as SMBError {
            switch err {
            case .notConnected: break  // expected
            default:
                XCTFail("Expected .notConnected, got \(err)")
            }
        } catch {
            XCTFail("Unexpected error type: \(error)")
        }
    }
}
