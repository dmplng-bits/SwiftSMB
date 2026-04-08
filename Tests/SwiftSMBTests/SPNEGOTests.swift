//
//  SPNEGOTests.swift
//  SwiftSMB
//
//  Created by Preet Singh on 4/7/26.
//

import XCTest
@testable import SwiftSMB

final class SPNEGOTests: XCTestCase {

    // ── NegTokenInit wrapping ───────────────────────────────────────────

    func testWrapNegTokenInit() throws {
        // Create a fake NTLM NEGOTIATE message
        let ntlmNeg = NTLMv2.negotiate()
        let spnego = SPNEGO.wrapNegTokenInit(ntlmNegotiate: ntlmNeg)

        // Should start with APPLICATION [0] tag = 0x60
        XCTAssertEqual(spnego[0], 0x60)

        // Parse it back with our ASN.1 decoder
        let root = try ASN1Decoder.parse(spnego)
        XCTAssertEqual(root.tag, 0x60)
        XCTAssertTrue(root.isConstructed)

        // Should contain the SPNEGO OID
        let oidNode = root.first(tag: ASN1Tag.oid)
        XCTAssertNotNil(oidNode)
        XCTAssertEqual(oidNode?.oidString, SPNEGO.spnegoOID)

        // Should contain a context [0] (NegTokenInit)
        let ctx0 = root.first(tag: 0xA0)
        XCTAssertNotNil(ctx0)

        // Inside that should be a SEQUENCE with context [0] (mechTypes)
        // and context [2] (mechToken)
        let innerSeq = ctx0?.children.first
        XCTAssertNotNil(innerSeq)
        XCTAssertEqual(innerSeq?.tag, ASN1Tag.sequence)

        // mechTypes [0] should contain NTLMSSP OID
        let mechTypes = innerSeq?.first(tag: 0xA0)
        XCTAssertNotNil(mechTypes)
        let ntlmOid = mechTypes?.first(tag: ASN1Tag.oid)
        XCTAssertEqual(ntlmOid?.oidString, SPNEGO.ntlmsspOID)

        // mechToken [2] should contain an OCTET STRING with our NTLM message
        let mechToken = innerSeq?.first(tag: 0xA2)
        XCTAssertNotNil(mechToken)
        let octet = mechToken?.first(tag: ASN1Tag.octetString)
        XCTAssertNotNil(octet)
        // The OCTET STRING value should be the original NTLM negotiate
        XCTAssertEqual(octet?.data, ntlmNeg)
    }

    // ── NegTokenResp wrapping ───────────────────────────────────────────

    func testWrapNegTokenResp() throws {
        let ntlmAuth = Data(repeating: 0xAA, count: 32)
        let spnego = SPNEGO.wrapNegTokenResp(ntlmAuthenticate: ntlmAuth)

        // Should start with context [1] tag = 0xA1
        XCTAssertEqual(spnego[0], 0xA1)

        // Parse and verify structure
        let root = try ASN1Decoder.parse(spnego)
        XCTAssertEqual(root.tag, 0xA1)

        // Should contain a SEQUENCE
        let seq = root.children.first
        XCTAssertEqual(seq?.tag, ASN1Tag.sequence)

        // responseToken [2] → OCTET STRING with our NTLM auth
        let ctx2 = seq?.first(tag: 0xA2)
        XCTAssertNotNil(ctx2)
        let octet = ctx2?.first(tag: ASN1Tag.octetString)
        XCTAssertEqual(octet?.data, ntlmAuth)
    }

    // ── NegTokenResp parsing ────────────────────────────────────────────

    func testParseNegTokenResp() throws {
        // Build a synthetic NegTokenResp like a server would send.
        let ntlmChallenge = Data(repeating: 0xCC, count: 48)

        let inner = ASN1Encoder.sequence([
            // [0] negResult = acceptIncomplete (1)
            ASN1Encoder.context(0, value: ASN1Encoder.enumerated(1)),
            // [1] supportedMech = NTLMSSP OID
            ASN1Encoder.context(1, value: ASN1Encoder.oid(SPNEGO.ntlmsspOID)),
            // [2] responseToken = NTLM CHALLENGE
            ASN1Encoder.context(2, value: ASN1Encoder.octetString(ntlmChallenge)),
        ])
        let negTokenResp = ASN1Encoder.context(1, value: inner)

        let fields = try SPNEGO.parseNegTokenResp(negTokenResp)

        XCTAssertEqual(fields.negResult, .acceptIncomplete)
        XCTAssertEqual(fields.supportedMech, SPNEGO.ntlmsspOID)
        XCTAssertEqual(fields.responseToken, ntlmChallenge)
        XCTAssertNil(fields.mechListMIC)
    }

    func testExtractNTLMToken() throws {
        let ntlmChallenge = Data(repeating: 0xDD, count: 64)

        let inner = ASN1Encoder.sequence([
            ASN1Encoder.context(0, value: ASN1Encoder.enumerated(1)),
            ASN1Encoder.context(2, value: ASN1Encoder.octetString(ntlmChallenge)),
        ])
        let negTokenResp = ASN1Encoder.context(1, value: inner)

        let token = try SPNEGO.extractNTLMToken(negTokenResp)
        XCTAssertEqual(token, ntlmChallenge)
    }

    func testExtractNTLMTokenThrowsWhenMissing() {
        // NegTokenResp with no responseToken
        let inner = ASN1Encoder.sequence([
            ASN1Encoder.context(0, value: ASN1Encoder.enumerated(2)),  // reject
        ])
        let negTokenResp = ASN1Encoder.context(1, value: inner)

        XCTAssertThrowsError(try SPNEGO.extractNTLMToken(negTokenResp)) { error in
            XCTAssertEqual(error as? SMBError, .spnegoDecodeFailed)
        }
    }

    // ── Full round-trip: wrap → parse ───────────────────────────────────

    func testNegTokenRespRoundTrip() throws {
        // Simulate: client wraps an AUTHENTICATE, then parses it back
        // (as if we were the server).
        let ntlmAuth = NTLMv2.authenticate(
            flags: 0x00088207,
            ntChallengeResponse: Data(repeating: 0xEE, count: 24),
            domain: "WORKGROUP",
            user: "admin"
        )
        let wrapped = SPNEGO.wrapNegTokenResp(ntlmAuthenticate: ntlmAuth)

        // Parse it back
        let fields = try SPNEGO.parseNegTokenResp(wrapped)
        XCTAssertNotNil(fields.responseToken)
        XCTAssertEqual(fields.responseToken, ntlmAuth)
    }

    // ── Edge: negResult acceptCompleted ──────────────────────────────────

    func testAcceptCompletedParsing() throws {
        let inner = ASN1Encoder.sequence([
            ASN1Encoder.context(0, value: ASN1Encoder.enumerated(0)),
        ])
        let negTokenResp = ASN1Encoder.context(1, value: inner)

        let fields = try SPNEGO.parseNegTokenResp(negTokenResp)
        XCTAssertEqual(fields.negResult, .acceptCompleted)
        XCTAssertNil(fields.responseToken)
    }

    // ── Edge: reject ────────────────────────────────────────────────────

    func testRejectParsing() throws {
        let inner = ASN1Encoder.sequence([
            ASN1Encoder.context(0, value: ASN1Encoder.enumerated(2)),
        ])
        let negTokenResp = ASN1Encoder.context(1, value: inner)

        let fields = try SPNEGO.parseNegTokenResp(negTokenResp)
        XCTAssertEqual(fields.negResult, .reject)
    }
}
