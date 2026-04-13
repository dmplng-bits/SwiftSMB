//
//  ByteBuffer.swift
//  SwiftSMB
//
//  Created by Preet Singh on 4/7/26.
//
// Low-level byte I/O used throughout the SMB2 stack.
//
// SMB2 is entirely little-endian. Every integer on the wire is LE.
// ByteWriter lets us build packets field by field.
// ByteReader lets us parse responses field by field with cursor tracking.
//
// These are the only two types needed to implement the full SMB2 protocol —
// every packet in every future step is built with these two structs.

import Foundation

// MARK: - ByteWriter

/// Builds a binary packet by appending typed fields.
/// All multi-byte integers are written little-endian.
///
/// Example:
///   var w = ByteWriter()
///   w.uint16le(64)          // SMB2 header StructureSize
///   w.uint32le(0x00000001)  // some flags
///   let packet = w.data
public struct ByteWriter {

    /// The accumulated bytes. Read this when you're done building.
    public private(set) var data = Data()

    public init() {}

    // ── Integer fields (little-endian) ───────────────────────────────────

    @discardableResult
    public mutating func uint8(_ v: UInt8) -> Self {
        data.append(v)
        return self
    }

    @discardableResult
    public mutating func uint16le(_ v: UInt16) -> Self {
        data.append(UInt8( v        & 0xFF))
        data.append(UInt8((v >>  8) & 0xFF))
        return self
    }

    @discardableResult
    public mutating func uint32le(_ v: UInt32) -> Self {
        data.append(UInt8( v        & 0xFF))
        data.append(UInt8((v >>  8) & 0xFF))
        data.append(UInt8((v >> 16) & 0xFF))
        data.append(UInt8((v >> 24) & 0xFF))
        return self
    }

    @discardableResult
    public mutating func uint64le(_ v: UInt64) -> Self {
        for shift in stride(from: 0, through: 56, by: 8) {
            data.append(UInt8((v >> shift) & 0xFF))
        }
        return self
    }

    // ── Raw bytes ────────────────────────────────────────────────────────

    @discardableResult
    public mutating func bytes(_ d: Data) -> Self {
        data.append(d)
        return self
    }

    /// Append `n` zero bytes (padding / reserved fields).
    @discardableResult
    public mutating func zeros(_ n: Int) -> Self {
        data.append(Data(count: n))
        return self
    }

    // ── String encoding ───────────────────────────────────────────────────

    /// Overwrite a single byte at the given offset from the start of `data`.
    /// Used to patch fields (e.g. frag_length) after the full packet is built.
    public mutating func patch(_ value: UInt8, at offset: Int) {
        data[data.startIndex + offset] = value
    }

    /// Overwrite a UInt16 (little-endian) starting at the given offset.
    public mutating func patchUint16le(_ value: UInt16, at offset: Int) {
        data[data.startIndex + offset]     = UInt8(value & 0xFF)
        data[data.startIndex + offset + 1] = UInt8(value >> 8)
    }

    /// Append a Swift String encoded as UTF-16 little-endian.
    /// SMB2 uses UTF-16LE for all path and name fields.
    @discardableResult
    public mutating func utf16le(_ s: String) -> Self {
        for codeUnit in s.utf16 {
            data.append(UInt8( codeUnit        & 0xFF))
            data.append(UInt8((codeUnit >>  8) & 0xFF))
        }
        return self
    }
}

// MARK: - ByteReader

/// Parses a binary packet by reading typed fields in sequence.
/// Tracks a cursor so you read fields in order.
///
/// Example:
///   var r = ByteReader(responseData)
///   let structSize = try r.uint16le()   // reads 2 bytes, advances cursor
///   let flags      = try r.uint32le()   // reads 4 bytes, advances cursor
public struct ByteReader {

    private let data: Data
    /// Current read position (index into `data`, relative to `data.startIndex`).
    public private(set) var cursor: Int = 0

    public var remaining: Int { data.count - cursor }
    public var atEnd:     Bool { cursor >= data.count }

    public init(_ data: Data) {
        self.data = data
    }

    // ── Sequential reads (advance cursor) ───────────────────────────────

    public mutating func uint8() throws -> UInt8 {
        try need(1)
        defer { cursor += 1 }
        return data[data.startIndex + cursor]
    }

    public mutating func uint16le() throws -> UInt16 {
        try need(2)
        defer { cursor += 2 }
        return UInt16(data[data.startIndex + cursor]) |
               UInt16(data[data.startIndex + cursor + 1]) << 8
    }

    public mutating func uint32le() throws -> UInt32 {
        try need(4)
        defer { cursor += 4 }
        let base = data.startIndex + cursor
        return UInt32(data[base])     |
               UInt32(data[base + 1]) << 8  |
               UInt32(data[base + 2]) << 16 |
               UInt32(data[base + 3]) << 24
    }

    public mutating func uint64le() throws -> UInt64 {
        try need(8)
        defer { cursor += 8 }
        return (0..<8).reduce(UInt64(0)) { acc, i in
            acc | UInt64(data[data.startIndex + cursor + i]) << (i * 8)
        }
    }

    public mutating func bytes(_ n: Int) throws -> Data {
        try need(n)
        defer { cursor += n }
        return data[data.startIndex + cursor ..< data.startIndex + cursor + n]
    }

    /// Skip `n` bytes without reading them (reserved / padding fields).
    public mutating func skip(_ n: Int) throws {
        try need(n)
        cursor += n
    }

    /// Read everything from the current cursor to the end.
    public mutating func rest() -> Data {
        let result = Data(data.suffix(from: data.startIndex + cursor))
        cursor = data.count
        return result
    }

    // ── Random-access reads (do NOT advance cursor) ───────────────────────
    // Used when a packet contains an offset field that points to data
    // somewhere else in the same buffer — common in SMB2 responses.

    public func uint8(at offset: Int) -> UInt8 {
        guard offset < data.count else { return 0 }
        return data[data.startIndex + offset]
    }

    public func uint16le(at offset: Int) -> UInt16 {
        guard offset + 1 < data.count else { return 0 }
        return UInt16(data[data.startIndex + offset]) |
               UInt16(data[data.startIndex + offset + 1]) << 8
    }

    public func uint32le(at offset: Int) -> UInt32 {
        guard offset + 3 < data.count else { return 0 }
        let base = data.startIndex + offset
        return UInt32(data[base])     |
               UInt32(data[base + 1]) << 8  |
               UInt32(data[base + 2]) << 16 |
               UInt32(data[base + 3]) << 24
    }

    public func uint64le(at offset: Int) -> UInt64 {
        guard offset + 7 < data.count else { return 0 }
        return (0..<8).reduce(UInt64(0)) { acc, i in
            acc | UInt64(data[data.startIndex + offset + i]) << (i * 8)
        }
    }

    public func subdata(at offset: Int, length: Int) -> Data {
        guard offset >= 0, length > 0, offset + length <= data.count else { return Data() }
        return data[data.startIndex + offset ..< data.startIndex + offset + length]
    }

    // MARK: Private

    private func need(_ n: Int) throws {
        guard cursor + n <= data.count else {
            throw SMBError.truncatedPacket
        }
    }
}

// MARK: - String ↔ UTF-16LE helpers

extension String {
    /// Encode as UTF-16 little-endian Data.
    /// SMB2 uses this encoding for all path, filename, and name fields.
    public var utf16leData: Data {
        var d = Data()
        for cu in utf16 {
            d.append(UInt8( cu       & 0xFF))
            d.append(UInt8((cu >> 8) & 0xFF))
        }
        return d
    }
}

extension Data {
    /// Decode UTF-16LE bytes into a Swift String.
    public var utf16leString: String {
        let codeUnits = stride(from: 0, to: count - 1, by: 2).map { i -> UInt16 in
            UInt16(self[startIndex + i]) | UInt16(self[startIndex + i + 1]) << 8
        }
        return String(decoding: codeUnits, as: UTF16.self)
    }

    /// Hex string for debugging (e.g. "fe 53 4d 42 ...")
    public var hexDump: String {
        map { String(format: "%02x", $0) }.joined(separator: " ")
    }
}
