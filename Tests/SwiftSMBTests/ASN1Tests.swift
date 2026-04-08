//
//  ASN1Tests.swift
//  SwiftSMB
//
//  Created by Preet Singh on 4/7/26.
//

import XCTest
@testable import SwiftSMB

final class ASN1Tests: XCTestCase {

    // ── Length encoding ─────────────────────────────────────────────────

    func testShortLength() {
        let encoded = ASN1Encoder.encodeLength(5)
        XCTAssertEqual(encoded, [0x05])
    }

    func testLength127() {
        let encoded = ASN1Encoder.encodeLength(127)
        XCTAssertEqual(encoded, [0x7F])
    }

    func testLength128() {
        let encoded = ASN1Encoder.encodeLength(128)
        XCTAssertEqual(encoded, [0x81, 0x80])
    }

    func testLength256() {
        let encoded = ASN1Encoder.encodeLength(256)
        XCTAssertEqual(encoded, [0x82, 0x01, 0x00])
    }

    // ── OID encoding / decoding ─────────────────────────────────────────

    func testOIDEncodeDecode() {
        let oidString = "1.3.6.1.5.5.2"
        let encoded = ASN1Encoder.oid(oidString)
        let node = try! ASN1Decoder.parse(encoded)
        XCTAssertEqual(node.tag, ASN1Tag.oid)
        XCTAssertEqual(node.oidString, oidString)
    }

    func testNTLMSSPOID() {
        // The NTLMSSP OID has a large component (311) that requires
        // multi-byte base-128 encoding.
        let oidString = "1.3.6.1.4.1.311.2.2.10"
        let encoded = ASN1Encoder.oid(oidString)
        let node = try! ASN1Decoder.parse(encoded)
        XCTAssertEqual(node.oidString, oidString)
    }

    // ── Primitive encode/decode round-trip ───────────────────────────────

    func testOctetStringRoundTrip() {
        let original = Data([0xDE, 0xAD, 0xBE, 0xEF])
        let encoded = ASN1Encoder.octetString(original)
        let node = try! ASN1Decoder.parse(encoded)
        XCTAssertEqual(node.tag, ASN1Tag.octetString)
        XCTAssertEqual(node.data, original)
    }

    func testEnumeratedRoundTrip() {
        let encoded = ASN1Encoder.enumerated(1)
        let node = try! ASN1Decoder.parse(encoded)
        XCTAssertEqual(node.tag, ASN1Tag.enumerated)
        XCTAssertEqual(node.data, Data([0x01]))
    }

    // ── Sequence encoding / decoding ────────────────────────────────────

    func testSequenceWithChildren() {
        let child1 = ASN1Encoder.oid("1.2.3")
        let child2 = ASN1Encoder.octetString(Data([0x01, 0x02]))
        let seq = ASN1Encoder.sequence([child1, child2])

        let node = try! ASN1Decoder.parse(seq)
        XCTAssertEqual(node.tag, ASN1Tag.sequence)
        XCTAssertTrue(node.isConstructed)
        XCTAssertEqual(node.children.count, 2)
        XCTAssertEqual(node.children[0].oidString, "1.2.3")
        XCTAssertEqual(node.children[1].data, Data([0x01, 0x02]))
    }

    // ── Context-tagged ──────────────────────────────────────────────────

    func testContextTagConstructed() {
        let inner = ASN1Encoder.octetString(Data([0xFF]))
        let tagged = ASN1Encoder.context(0, constructed: true, value: inner)

        let node = try! ASN1Decoder.parse(tagged)
        XCTAssertEqual(node.tag, 0xA0)
        XCTAssertTrue(node.isConstructed)
        XCTAssertEqual(node.children.count, 1)
        XCTAssertEqual(node.children[0].data, Data([0xFF]))
    }

    func testContextTag2() {
        let inner = ASN1Encoder.enumerated(2)
        let tagged = ASN1Encoder.context(2, constructed: true, value: inner)

        let node = try! ASN1Decoder.parse(tagged)
        XCTAssertEqual(node.tag, 0xA2)
        XCTAssertEqual(node.children.count, 1)
    }

    // ── Nested structures ───────────────────────────────────────────────

    func testNestedSequences() {
        let innerSeq = ASN1Encoder.sequence([
            ASN1Encoder.oid("1.2.3.4")
        ])
        let outerSeq = ASN1Encoder.sequence([
            innerSeq,
            ASN1Encoder.octetString(Data([0xAA, 0xBB]))
        ])

        let node = try! ASN1Decoder.parse(outerSeq)
        XCTAssertEqual(node.children.count, 2)
        XCTAssertEqual(node.children[0].children.count, 1)
        XCTAssertEqual(node.children[0].children[0].oidString, "1.2.3.4")
    }

    // ── Node search helpers ─────────────────────────────────────────────

    func testFirstByTag() {
        let seq = ASN1Encoder.sequence([
            ASN1Encoder.oid("1.2.3"),
            ASN1Encoder.context(0, value: ASN1Encoder.enumerated(1)),
            ASN1Encoder.context(2, value: ASN1Encoder.octetString(Data([0x42])))
        ])

        let node = try! ASN1Decoder.parse(seq)
        let found = node.first(tag: 0xA2)
        XCTAssertNotNil(found)
        XCTAssertEqual(found?.tag, 0xA2)
    }

    // ── Error handling ──────────────────────────────────────────────────

    func testTruncatedInput() {
        let truncated = Data([0x30, 0x10])  // SEQUENCE claiming 16 bytes but data ends
        XCTAssertThrowsError(try ASN1Decoder.parse(truncated))
    }

    func testEmptyInput() {
        XCTAssertThrowsError(try ASN1Decoder.parse(Data()))
    }

    // ── parseAll for multiple top-level nodes ───────────────────────────

    func testParseAll() {
        let oid1 = ASN1Encoder.oid("1.2.3")
        let oid2 = ASN1Encoder.oid("4.5.6")
        let combined = oid1 + oid2

        let nodes = try! ASN1Decoder.parseAll(combined)
        XCTAssertEqual(nodes.count, 2)
        XCTAssertEqual(nodes[0].oidString, "1.2.3")
        XCTAssertEqual(nodes[1].oidString, "4.5.6")
    }
}
