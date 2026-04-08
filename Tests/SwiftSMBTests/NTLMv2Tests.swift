//
//  NTLMv2Tests.swift
//  SwiftSMB
//
//  Created by Preet Singh on 4/7/26.
//

import XCTest
@testable import SwiftSMB

final class NTLMv2Tests: XCTestCase {

    // ── MS-NLMP §4.2.4 test vectors ────────────────────────────────────
    // Reference: [MS-NLMP] Section 4.2.4 NTLMv2 Authentication
    //
    // Test values from the Microsoft specification:
    //   User:     "User"
    //   Domain:   "Domain"
    //   Password: "Password"

    let testUser     = "User"
    let testDomain   = "Domain"
    let testPassword = "Password"

    // ── NT Hash ─────────────────────────────────────────────────────────

    func testNTHash() {
        let hash = NTLMv2.ntHash(password: testPassword)
        // MD4(UTF-16LE("Password")) = a4f49c406510bdcab6824ee7c30fd852
        XCTAssertEqual(hash.hexDump, "a4 f4 9c 40 65 10 bd ca b6 82 4e e7 c3 0f d8 52")
    }

    // ── NTLMv2 Hash ─────────────────────────────────────────────────────

    func testNTLMv2Hash() {
        let nt = NTLMv2.ntHash(password: testPassword)
        let v2hash = NTLMv2.ntlmv2Hash(ntHash: nt, user: testUser, domain: testDomain)
        // HMAC-MD5(ntHash, UTF-16LE("USERDomain"))
        XCTAssertEqual(v2hash.count, 16)
        // The expected value from MS-NLMP §4.2.4.1.1:
        XCTAssertEqual(v2hash.hexDump, "0c 86 8a 40 3b fd 7a 93 a3 00 1e f2 2e f0 2e 3f")
    }

    // ── Negotiate message (Type 1) ──────────────────────────────────────

    func testNegotiateMessage() {
        let msg = NTLMv2.negotiate()

        // Must start with NTLMSSP signature
        XCTAssertEqual(Data(msg.prefix(8)), NTLMv2.signature)

        // Type must be 1 (NEGOTIATE)
        var r = ByteReader(msg)
        try! r.skip(8)
        let msgType = try! r.uint32le()
        XCTAssertEqual(msgType, NTLMv2.typeNegotiate)

        // Flags should include UNICODE and NTLM
        let flags = try! r.uint32le()
        XCTAssertTrue(flags & 0x01 != 0,  "UNICODE flag should be set")
        XCTAssertTrue(flags & 0x200 != 0, "NTLM flag should be set")
    }

    // ── Challenge parsing (Type 2) ──────────────────────────────────────

    func testParseSyntheticChallenge() {
        // Build a minimal Type 2 message for testing.
        let challenge = buildTestChallenge()
        let parsed = try! NTLMv2.parseChallenge(challenge)

        XCTAssertEqual(parsed.serverChallenge.count, 8)
        XCTAssertEqual(parsed.serverChallenge, Data([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]))
    }

    func testParseChallengeRejectsInvalidSignature() {
        var bad = buildTestChallenge()
        bad[0] = 0xFF  // corrupt signature
        XCTAssertThrowsError(try NTLMv2.parseChallenge(bad)) { error in
            XCTAssertEqual(error as? SMBError, .invalidNTLMMessage)
        }
    }

    // ── Authenticate message (Type 3) ───────────────────────────────────

    func testAuthenticateMessage() {
        let fakeResponse = Data(repeating: 0xAA, count: 24)
        let msg = NTLMv2.authenticate(
            flags: 0x00088207,
            ntChallengeResponse: fakeResponse,
            domain: testDomain,
            user: testUser,
            workstation: "WORKSTATION"
        )

        // Must start with NTLMSSP signature
        XCTAssertEqual(Data(msg.prefix(8)), NTLMv2.signature)

        // Type must be 3 (AUTHENTICATE)
        var r = ByteReader(msg)
        try! r.skip(8)
        let msgType = try! r.uint32le()
        XCTAssertEqual(msgType, NTLMv2.typeAuthenticate)
    }

    // ── Challenge-response computation ──────────────────────────────────

    func testComputeResponse() {
        let nt = NTLMv2.ntHash(password: testPassword)
        let v2hash = NTLMv2.ntlmv2Hash(ntHash: nt, user: testUser, domain: testDomain)
        let serverChallenge = Data([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF])
        let clientBlob = Data(repeating: 0xBB, count: 32)

        let (ntProofStr, ntChallengeResponse, sessionBaseKey) =
            NTLMv2.computeResponse(
                ntlmv2Hash: v2hash,
                serverChallenge: serverChallenge,
                clientBlob: clientBlob
            )

        // ntProofStr is HMAC-MD5, should be 16 bytes
        XCTAssertEqual(ntProofStr.count, 16)
        // ntChallengeResponse = ntProofStr + clientBlob
        XCTAssertEqual(ntChallengeResponse.count, 16 + clientBlob.count)
        XCTAssertEqual(Data(ntChallengeResponse.prefix(16)), ntProofStr)
        // sessionBaseKey is HMAC-MD5, should be 16 bytes
        XCTAssertEqual(sessionBaseKey.count, 16)
    }

    // ── Client blob ─────────────────────────────────────────────────────

    func testClientBlob() {
        let timestamp: UInt64 = 0x0000_0000_0000_0001
        let clientChallenge = Data(repeating: 0xCC, count: 8)
        let targetInfo = Data([0x02, 0x00, 0x06, 0x00] + "SMB".utf16leData.prefix(6) + [0x00, 0x00, 0x00, 0x00])

        let blob = NTLMv2.buildClientBlob(
            timestamp: timestamp,
            clientChallenge: clientChallenge,
            targetInfo: targetInfo
        )

        // Blob starts with 0x01 0x01
        XCTAssertEqual(blob[0], 0x01)
        XCTAssertEqual(blob[1], 0x01)

        // Check the client challenge is embedded at offset 24
        // (1 + 1 + 2 + 4 + 8 + 8 = 24 bytes of headers before challenge)
        // Actually: 1(respType) + 1(hiRespType) + 2(res1) + 4(res2) + 8(timestamp) = 16
        XCTAssertEqual(Data(blob[16..<24]), clientChallenge)
    }

    // ── AV_PAIR parsing ─────────────────────────────────────────────────

    func testParseAvPairs() {
        // Build a minimal AV_PAIR list: NbDomainName = "TEST", then EOL
        let domainName = "TEST".utf16leData
        var avData = Data()
        // MsvAvNbDomainName (0x0002), length
        avData.append(contentsOf: [0x02, 0x00])
        avData.append(contentsOf: [UInt8(domainName.count), 0x00])
        avData.append(domainName)
        // MsvAvEOL
        avData.append(contentsOf: [0x00, 0x00, 0x00, 0x00])

        let pairs = NTLMv2.parseAvPairs(avData)
        XCTAssertEqual(pairs.count, 1)
        XCTAssertNotNil(pairs[NTLMv2.AvId.nbDomainName])
        XCTAssertEqual(pairs[NTLMv2.AvId.nbDomainName]?.utf16leString, "TEST")
    }

    // ── FileTime ────────────────────────────────────────────────────────

    func testCurrentFileTime() {
        let ft = NTLMv2.currentFileTime()
        // Should be a large number > the epoch delta
        XCTAssertTrue(ft > 116_444_736_000_000_000)
    }

    // ── Random challenge ────────────────────────────────────────────────

    func testRandomChallenge() {
        let c1 = NTLMv2.randomChallenge()
        let c2 = NTLMv2.randomChallenge()
        XCTAssertEqual(c1.count, 8)
        XCTAssertEqual(c2.count, 8)
        // Two random challenges should (almost certainly) differ
        XCTAssertNotEqual(c1, c2)
    }

    // MARK: - Helpers

    /// Build a minimal synthetic Type 2 (CHALLENGE) message for testing.
    private func buildTestChallenge() -> Data {
        let targetName = "Domain".utf16leData
        let targetInfo = Data([0x00, 0x00, 0x00, 0x00])  // minimal: just EOL

        var w = ByteWriter()
        w.bytes(NTLMv2.signature)          // 8 bytes
        w.uint32le(NTLMv2.typeChallenge)   // 4 bytes → offset 12

        // TargetNameFields
        let tnOffset: UInt32 = 56  // after fixed header
        w.uint16le(UInt16(targetName.count))  // len
        w.uint16le(UInt16(targetName.count))  // maxLen
        w.uint32le(tnOffset)                  // offset

        // NegotiateFlags
        w.uint32le(0x00088207)

        // ServerChallenge (8 bytes)
        w.bytes(Data([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]))

        // Reserved (8 bytes)
        w.zeros(8)

        // TargetInfoFields
        let tiOffset = tnOffset + UInt32(targetName.count)
        w.uint16le(UInt16(targetInfo.count))
        w.uint16le(UInt16(targetInfo.count))
        w.uint32le(tiOffset)

        // Payload
        w.bytes(targetName)
        w.bytes(targetInfo)

        return w.data
    }
}
