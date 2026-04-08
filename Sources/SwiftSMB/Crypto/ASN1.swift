//
//  ASN1.swift
//  SwiftSMB
//
//  Created by Preet Singh on 4/7/26.
//
// Lightweight ASN.1 DER encoder / decoder.
//
// Supports the subset needed for SPNEGO: SEQUENCE, OID, OCTET STRING,
// ENUMERATED, BIT STRING, BOOLEAN, and context-tagged (implicit/explicit)
// constructed/primitive types. This is a proper generic codec — not
// hard-coded to specific SPNEGO byte patterns.
//
// ASN.1 DER encodes every element as: Tag | Length | Value (TLV).

import Foundation

// MARK: - ASN.1 Tag constants

/// Well-known ASN.1 universal tags.
public enum ASN1Tag {
    public static let boolean:       UInt8 = 0x01
    public static let integer:       UInt8 = 0x02
    public static let bitString:     UInt8 = 0x03
    public static let octetString:   UInt8 = 0x04
    public static let null:          UInt8 = 0x05
    public static let oid:           UInt8 = 0x06
    public static let enumerated:    UInt8 = 0x0A
    public static let utf8String:    UInt8 = 0x0C
    public static let sequence:      UInt8 = 0x30  // CONSTRUCTED SEQUENCE
    public static let set:           UInt8 = 0x31  // CONSTRUCTED SET

    /// Build a context-tagged tag byte.
    ///   - `number`:      context tag number (0–30)
    ///   - `constructed`: true for SEQUENCE-like wrappers
    public static func context(_ number: UInt8, constructed: Bool = true) -> UInt8 {
        let base: UInt8 = constructed ? 0xA0 : 0x80
        return base | (number & 0x1F)
    }
}

// MARK: - ASN.1 Node (parsed tree)

/// A single parsed ASN.1 DER node.
public struct ASN1Node: CustomDebugStringConvertible {
    public let tag: UInt8
    public let data: Data           // the raw value bytes (V of TLV)
    public var children: [ASN1Node] // non-empty for constructed types

    public init(tag: UInt8, data: Data, children: [ASN1Node] = []) {
        self.tag = tag
        self.data = data
        self.children = children
    }

    /// True when the tag indicates a constructed (container) type.
    public var isConstructed: Bool { tag & 0x20 != 0 }

    /// Extract the OID as a dot-separated string (e.g. "1.3.6.1.5.5.2").
    public var oidString: String? {
        guard tag == ASN1Tag.oid, !data.isEmpty else { return nil }
        var components: [UInt64] = []
        let first = data[data.startIndex]
        components.append(UInt64(first / 40))
        components.append(UInt64(first % 40))

        var value: UInt64 = 0
        for i in 1..<data.count {
            let byte = data[data.startIndex + i]
            value = (value << 7) | UInt64(byte & 0x7F)
            if byte & 0x80 == 0 {
                components.append(value)
                value = 0
            }
        }
        return components.map(String.init).joined(separator: ".")
    }

    /// Find the first child (recursive) matching a tag.
    public func first(tag: UInt8) -> ASN1Node? {
        for child in children {
            if child.tag == tag { return child }
            if let found = child.first(tag: tag) { return found }
        }
        return nil
    }

    /// Find all immediate children matching a tag.
    public func children(tag: UInt8) -> [ASN1Node] {
        children.filter { $0.tag == tag }
    }

    public var debugDescription: String {
        let tagHex = String(format: "0x%02X", tag)
        if children.isEmpty {
            return "ASN1Node(\(tagHex), \(data.count) bytes)"
        }
        return "ASN1Node(\(tagHex), \(children.count) children)"
    }
}

// MARK: - ASN.1 DER Decoder

public enum ASN1Decoder {

    /// Parse a DER-encoded byte sequence into a tree of ASN1Nodes.
    /// Throws `SMBError.spnegoDecodeFailed` on malformed input.
    public static func parse(_ data: Data) throws -> ASN1Node {
        var reader = DERReader(data)
        return try reader.readNode()
    }

    /// Parse all top-level nodes in `data` (if there are multiple).
    public static func parseAll(_ data: Data) throws -> [ASN1Node] {
        var reader = DERReader(data)
        var nodes: [ASN1Node] = []
        while !reader.atEnd {
            nodes.append(try reader.readNode())
        }
        return nodes
    }
}

private struct DERReader {
    private let data: Data
    private var cursor: Int

    var atEnd: Bool { cursor >= data.count }

    init(_ data: Data) {
        self.data = data
        self.cursor = 0
    }

    mutating func readNode() throws -> ASN1Node {
        let tag = try readByte()
        let length = try readLength()
        let valueStart = cursor

        guard cursor + length <= data.count else {
            throw SMBError.spnegoDecodeFailed
        }

        // Constructed types: parse children recursively.
        if tag & 0x20 != 0 {
            var children: [ASN1Node] = []
            let valueEnd = cursor + length
            while cursor < valueEnd {
                children.append(try readNode())
            }
            let nodeData = Data(data[data.startIndex + valueStart ..< data.startIndex + valueEnd])
            return ASN1Node(tag: tag, data: nodeData, children: children)
        } else {
            // Primitive type: just capture the value bytes.
            let value = Data(data[data.startIndex + cursor ..< data.startIndex + cursor + length])
            cursor += length
            return ASN1Node(tag: tag, data: value)
        }
    }

    private mutating func readByte() throws -> UInt8 {
        guard cursor < data.count else { throw SMBError.spnegoDecodeFailed }
        defer { cursor += 1 }
        return data[data.startIndex + cursor]
    }

    /// DER length decoding: short form (1 byte) or long form (2–5 bytes).
    private mutating func readLength() throws -> Int {
        let first = try readByte()
        if first < 0x80 {
            return Int(first)
        }
        let numBytes = Int(first & 0x7F)
        guard numBytes >= 1, numBytes <= 4 else { throw SMBError.spnegoDecodeFailed }
        var length = 0
        for _ in 0..<numBytes {
            length = (length << 8) | Int(try readByte())
        }
        guard length >= 0, length <= 0x7FFF_FFFF else { throw SMBError.spnegoDecodeFailed }
        return length
    }
}

// MARK: - ASN.1 DER Encoder

public enum ASN1Encoder {

    /// Encode a tag + raw value (primitive TLV).
    public static func primitive(tag: UInt8, value: Data) -> Data {
        var result = Data()
        result.append(tag)
        result.append(contentsOf: encodeLength(value.count))
        result.append(value)
        return result
    }

    /// Encode a constructed TLV whose value is the concatenation of `children`.
    public static func constructed(tag: UInt8, children: [Data]) -> Data {
        let inner = children.reduce(Data()) { $0 + $1 }
        var result = Data()
        result.append(tag)
        result.append(contentsOf: encodeLength(inner.count))
        result.append(inner)
        return result
    }

    /// Convenience: SEQUENCE containing `children`.
    public static func sequence(_ children: [Data]) -> Data {
        constructed(tag: ASN1Tag.sequence, children: children)
    }

    /// Encode an OID from its dot-string form (e.g. "1.3.6.1.5.5.2").
    public static func oid(_ dotString: String) -> Data {
        let components = dotString.split(separator: ".").compactMap { UInt64($0) }
        guard components.count >= 2 else { return Data() }

        var bytes = Data()
        bytes.append(UInt8(components[0] * 40 + components[1]))
        for i in 2..<components.count {
            bytes.append(contentsOf: encodeOIDComponent(components[i]))
        }
        return primitive(tag: ASN1Tag.oid, value: bytes)
    }

    /// OCTET STRING wrapping raw bytes.
    public static func octetString(_ value: Data) -> Data {
        primitive(tag: ASN1Tag.octetString, value: value)
    }

    /// ENUMERATED (single integer value).
    public static func enumerated(_ value: UInt8) -> Data {
        primitive(tag: ASN1Tag.enumerated, value: Data([value]))
    }

    /// Context-tagged wrapper.
    public static func context(_ number: UInt8, constructed: Bool = true, value: Data) -> Data {
        let tag = ASN1Tag.context(number, constructed: constructed)
        if constructed {
            return self.constructed(tag: tag, children: [value])
        } else {
            return primitive(tag: tag, value: value)
        }
    }

    // MARK: - Length encoding

    static func encodeLength(_ length: Int) -> [UInt8] {
        if length < 0x80 {
            return [UInt8(length)]
        } else if length <= 0xFF {
            return [0x81, UInt8(length)]
        } else if length <= 0xFFFF {
            return [0x82, UInt8(length >> 8), UInt8(length & 0xFF)]
        } else if length <= 0xFF_FFFF {
            return [0x83, UInt8(length >> 16), UInt8((length >> 8) & 0xFF), UInt8(length & 0xFF)]
        } else {
            return [0x84,
                    UInt8(length >> 24), UInt8((length >> 16) & 0xFF),
                    UInt8((length >> 8) & 0xFF), UInt8(length & 0xFF)]
        }
    }

    // MARK: - OID component encoding (base-128)

    private static func encodeOIDComponent(_ value: UInt64) -> [UInt8] {
        if value < 128 {
            return [UInt8(value)]
        }
        var bytes: [UInt8] = []
        var v = value
        bytes.append(UInt8(v & 0x7F))
        v >>= 7
        while v > 0 {
            bytes.append(UInt8(v & 0x7F) | 0x80)
            v >>= 7
        }
        return bytes.reversed()
    }
}
