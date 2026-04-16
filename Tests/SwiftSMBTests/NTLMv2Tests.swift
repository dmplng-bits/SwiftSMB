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

    // ── Byte-exact Type 1 (NEGOTIATE) layout ───────────────────────────

    func testNegotiateLayout() {
        let msg = NTLMv2.negotiate()

        // Type 1 layout (§2.2.1.1):
        //   0..7   Signature "NTLMSSP\0"
        //   8..11  MessageType = 1
        //  12..15  NegotiateFlags
        //  16..23  DomainNameFields (len=0, maxLen=0, offset=0)
        //  24..31  WorkstationFields (len=0, maxLen=0, offset=0)
        //  32..39  Version (8 bytes)
        //  Total = 40 bytes
        XCTAssertEqual(msg.count, 40, "Type 1 must be exactly 40 bytes")

        // Signature
        XCTAssertEqual(Data(msg[0..<8]), Data("NTLMSSP\0".utf8))

        // MessageType = 1
        let msgType = UInt32(msg[8]) | UInt32(msg[9]) << 8
            | UInt32(msg[10]) << 16 | UInt32(msg[11]) << 24
        XCTAssertEqual(msgType, 1)

        // NegotiateFlags must include VERSION (0x0200_0000)
        let flags = UInt32(msg[12]) | UInt32(msg[13]) << 8
            | UInt32(msg[14]) << 16 | UInt32(msg[15]) << 24
        XCTAssertTrue(flags & NTLMv2.Flag.version != 0,
                       "VERSION flag must be set")

        // DomainNameFields: all zeros (no domain supplied)
        XCTAssertEqual(Data(msg[16..<24]), Data(count: 8))

        // WorkstationFields: all zeros
        XCTAssertEqual(Data(msg[24..<32]), Data(count: 8))

        // Version struct at offset 32:
        //   32: ProductMajorVersion = 10
        //   33: ProductMinorVersion = 0
        //   34..35: ProductBuild = 19041 (LE: 0x61, 0x4A)
        //   36..38: Reserved (3 zeros)
        //   39: NTLMRevisionCurrent = 0x0F
        XCTAssertEqual(msg[32], 10,   "ProductMajorVersion")
        XCTAssertEqual(msg[33], 0,    "ProductMinorVersion")
        XCTAssertEqual(msg[34], 0x61, "ProductBuild low byte")
        XCTAssertEqual(msg[35], 0x4A, "ProductBuild high byte")
        XCTAssertEqual(Data(msg[36..<39]), Data(count: 3), "Version reserved")
        XCTAssertEqual(msg[39], 0x0F, "NTLMRevisionCurrent")
    }

    // ── Byte-exact Type 3 (AUTHENTICATE) payload offsets ────────────────

    func testAuthenticatePayloadOffsets() {
        // Use known-size payloads so we can compute expected offsets.
        let ntResp   = Data(repeating: 0xBB, count: 48)
        let domain   = "TEST"
        let user     = "admin"
        let ws       = "PC01"

        let msg = NTLMv2.authenticate(
            flags: NTLMv2.defaultNegotiateFlags,
            ntChallengeResponse: ntResp,
            domain: domain,
            user: user,
            workstation: ws
        )

        // Fixed header = 72 bytes:
        //   Sig(8) + Type(4) + 6×SecBuf(48) + Flags(4) + Version(8) = 72
        let headerSize = 72

        // Payload order: LM(24) + NT(48) + Domain + User + WS + SK(0)
        let domBytes = domain.utf16leData  // 8 bytes
        let usrBytes = user.utf16leData    // 10 bytes
        let wsBytes  = ws.utf16leData      // 8 bytes

        let expectedLmOffset     = headerSize
        let expectedNtOffset     = expectedLmOffset + 24
        let expectedDomOffset    = expectedNtOffset + 48
        let expectedUserOffset   = expectedDomOffset + domBytes.count
        let expectedWsOffset     = expectedUserOffset + usrBytes.count
        let expectedSkOffset     = expectedWsOffset + wsBytes.count

        // Read security buffer descriptors from the message.
        // Each is: Length(2) + MaxLength(2) + Offset(4), starting at byte 12.
        func readSecBuf(at base: Int) -> (length: Int, offset: Int) {
            let len = Int(UInt16(msg[base]) | UInt16(msg[base+1]) << 8)
            let off = Int(UInt32(msg[base+4]) | UInt32(msg[base+5]) << 8
                       | UInt32(msg[base+6]) << 16 | UInt32(msg[base+7]) << 24)
            return (len, off)
        }

        let lmBuf     = readSecBuf(at: 12)   // LmChallengeResponseFields
        let ntBuf     = readSecBuf(at: 20)   // NtChallengeResponseFields
        let domBuf    = readSecBuf(at: 28)   // DomainNameFields
        let userBuf   = readSecBuf(at: 36)   // UserNameFields
        let wsBuf     = readSecBuf(at: 44)   // WorkstationFields
        let skBuf     = readSecBuf(at: 52)   // EncryptedRandomSessionKeyFields

        XCTAssertEqual(lmBuf.length, 24,            "LM response length")
        XCTAssertEqual(lmBuf.offset, expectedLmOffset, "LM response offset")

        XCTAssertEqual(ntBuf.length, 48,            "NT response length")
        XCTAssertEqual(ntBuf.offset, expectedNtOffset, "NT response offset")

        XCTAssertEqual(domBuf.length, domBytes.count, "Domain length")
        XCTAssertEqual(domBuf.offset, expectedDomOffset, "Domain offset")

        XCTAssertEqual(userBuf.length, usrBytes.count, "User length")
        XCTAssertEqual(userBuf.offset, expectedUserOffset, "User offset")

        XCTAssertEqual(wsBuf.length, wsBytes.count, "Workstation length")
        XCTAssertEqual(wsBuf.offset, expectedWsOffset, "Workstation offset")

        XCTAssertEqual(skBuf.length, 0,             "SK length (no key exchange)")
        XCTAssertEqual(skBuf.offset, expectedSkOffset, "SK offset")

        // Verify the actual payload bytes at the declared offsets match.
        let actualDom = Data(msg[domBuf.offset ..< domBuf.offset + domBuf.length])
        XCTAssertEqual(actualDom, domBytes, "Domain payload at offset must match UTF-16LE")

        let actualUser = Data(msg[userBuf.offset ..< userBuf.offset + userBuf.length])
        XCTAssertEqual(actualUser, usrBytes, "User payload at offset must match UTF-16LE")

        let actualWs = Data(msg[wsBuf.offset ..< wsBuf.offset + wsBuf.length])
        XCTAssertEqual(actualWs, wsBytes, "Workstation payload at offset must match UTF-16LE")

        let actualNt = Data(msg[ntBuf.offset ..< ntBuf.offset + ntBuf.length])
        XCTAssertEqual(actualNt, ntResp, "NT response payload at offset must match")
    }

    // ── Type 3 Version struct placement ─────────────────────────────────

    func testAuthenticateVersionStruct() {
        let msg = NTLMv2.authenticate(
            flags: NTLMv2.defaultNegotiateFlags,
            ntChallengeResponse: Data(repeating: 0xAA, count: 24),
            domain: "D",
            user: "U"
        )

        // Flags at offset 60..63
        let flags = UInt32(msg[60]) | UInt32(msg[61]) << 8
            | UInt32(msg[62]) << 16 | UInt32(msg[63]) << 24
        // KEY_EXCH must be stripped (no session key provided)
        XCTAssertEqual(flags & NTLMv2.Flag.keyExch, 0,
                        "KEY_EXCH must be stripped when no session key")
        // VERSION must remain set
        XCTAssertTrue(flags & NTLMv2.Flag.version != 0,
                       "VERSION flag must be set")

        // Version struct at offset 64..71
        XCTAssertEqual(msg[64], 10,   "ProductMajorVersion")
        XCTAssertEqual(msg[65], 0,    "ProductMinorVersion")
        XCTAssertEqual(msg[66], 0x61, "ProductBuild low")
        XCTAssertEqual(msg[67], 0x4A, "ProductBuild high")
        XCTAssertEqual(msg[71], 0x0F, "NTLMRevisionCurrent")
    }

    // ── Anonymous AUTHENTICATE layout ───────────────────────────────────

    func testAnonymousAuthenticateLayout() {
        let msg = NTLMv2.authenticateAnonymous(
            challengeFlags: NTLMv2.defaultNegotiateFlags,
            workstation: "WS"
        )

        // Signature + Type
        XCTAssertEqual(Data(msg[0..<8]), Data("NTLMSSP\0".utf8))
        let msgType = UInt32(msg[8]) | UInt32(msg[9]) << 8
            | UInt32(msg[10]) << 16 | UInt32(msg[11]) << 24
        XCTAssertEqual(msgType, 3)

        // Header = 72, payloads start there.
        let headerSize = 72

        func readSecBuf(at base: Int) -> (length: Int, offset: Int) {
            let len = Int(UInt16(msg[base]) | UInt16(msg[base+1]) << 8)
            let off = Int(UInt32(msg[base+4]) | UInt32(msg[base+5]) << 8
                       | UInt32(msg[base+6]) << 16 | UInt32(msg[base+7]) << 24)
            return (len, off)
        }

        let lmBuf   = readSecBuf(at: 12)
        let ntBuf   = readSecBuf(at: 20)
        let domBuf  = readSecBuf(at: 28)
        let userBuf = readSecBuf(at: 36)
        let wsBuf   = readSecBuf(at: 44)
        let skBuf   = readSecBuf(at: 52)

        // LM response = 1 byte (0x00), NT response = 0 bytes
        XCTAssertEqual(lmBuf.length, 1,  "Anonymous LM = 1 byte")
        XCTAssertEqual(lmBuf.offset, headerSize)
        XCTAssertEqual(ntBuf.length, 0,  "Anonymous NT = 0 bytes")

        // Domain and user must be empty
        XCTAssertEqual(domBuf.length, 0, "Anonymous domain empty")
        XCTAssertEqual(userBuf.length, 0, "Anonymous user empty")

        // Workstation = "WS" → 4 bytes UTF-16LE
        let wsBytes = "WS".utf16leData
        XCTAssertEqual(wsBuf.length, wsBytes.count)
        let actualWs = Data(msg[wsBuf.offset ..< wsBuf.offset + wsBuf.length])
        XCTAssertEqual(actualWs, wsBytes)

        // SK must be empty
        XCTAssertEqual(skBuf.length, 0)

        // Flags must have ANONYMOUS set and KEY_EXCH cleared
        let flags = UInt32(msg[60]) | UInt32(msg[61]) << 8
            | UInt32(msg[62]) << 16 | UInt32(msg[63]) << 24
        XCTAssertTrue(flags & NTLMv2.Flag.anonymous != 0, "ANONYMOUS flag set")
        XCTAssertEqual(flags & NTLMv2.Flag.keyExch, 0,    "KEY_EXCH cleared")

        // The single LM byte at the declared offset must be 0x00
        XCTAssertEqual(msg[lmBuf.offset], 0x00, "Anonymous LM byte = 0")
    }

    // ── KEY_EXCH stripping ──────────────────────────────────────────────

    func testKeyExchStrippedWithoutSessionKey() {
        let flags: UInt32 = NTLMv2.Flag.unicode | NTLMv2.Flag.ntlm | NTLMv2.Flag.keyExch
        let msg = NTLMv2.authenticate(
            flags: flags,
            ntChallengeResponse: Data(count: 16),
            domain: "D",
            user: "U"
        )

        let wireFlags = UInt32(msg[60]) | UInt32(msg[61]) << 8
            | UInt32(msg[62]) << 16 | UInt32(msg[63]) << 24
        XCTAssertEqual(wireFlags & NTLMv2.Flag.keyExch, 0,
                        "KEY_EXCH must be stripped when sessionBaseKey is nil")
    }

    func testKeyExchPreservedWithSessionKey() {
        let flags: UInt32 = NTLMv2.Flag.unicode | NTLMv2.Flag.ntlm | NTLMv2.Flag.keyExch
        let msg = NTLMv2.authenticate(
            flags: flags,
            ntChallengeResponse: Data(count: 16),
            domain: "D",
            user: "U",
            sessionBaseKey: Data(repeating: 0x42, count: 16)
        )

        let wireFlags = UInt32(msg[60]) | UInt32(msg[61]) << 8
            | UInt32(msg[62]) << 16 | UInt32(msg[63]) << 24
        XCTAssertTrue(wireFlags & NTLMv2.Flag.keyExch != 0,
                       "KEY_EXCH must be preserved when sessionBaseKey is provided")

        // Verify the session key payload is at the SK offset and has correct length
        let skLen = Int(UInt16(msg[52]) | UInt16(msg[53]) << 8)
        let skOff = Int(UInt32(msg[56]) | UInt32(msg[57]) << 8
                     | UInt32(msg[58]) << 16 | UInt32(msg[59]) << 24)
        XCTAssertEqual(skLen, 16)
        let actualSk = Data(msg[skOff ..< skOff + skLen])
        XCTAssertEqual(actualSk, Data(repeating: 0x42, count: 16))
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
