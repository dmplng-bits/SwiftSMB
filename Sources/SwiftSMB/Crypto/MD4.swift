//
//  MD4.swift
//  SwiftSMB
//
//  Created by Preet Singh on 4/7/26.
//
// Pure Swift MD4 hash (RFC 1320).
//
// MD4 is cryptographically broken — we implement it only because
// NTLMv2 requires MD4(UTF-16LE(password)) for the NT password hash.
// Apple's CryptoKit doesn't include MD4, so we roll our own.
//
// This implementation processes 512-bit blocks with three 16-operation
// rounds, producing a 128-bit (16-byte) digest.

import Foundation

// MARK: - Public API

/// Compute the MD4 digest of arbitrary data.
///
///     let hash = MD4.hash(data: "abc".data(using: .utf8)!)
///     // hash is 16 bytes: a4 48 01 7a af 21 d8 52 5f c1 0a e8 7a a6 72 9d
public enum MD4 {

    /// Returns the 16-byte MD4 digest of `data`.
    public static func hash(data: Data) -> Data {
        var state = MD4State()
        state.update(data)
        return state.finalize()
    }
}

// MARK: - Internal state machine

private struct MD4State {

    // Initial hash values (RFC 1320 §3.3)
    private var a: UInt32 = 0x6745_2301
    private var b: UInt32 = 0xEFCD_AB89
    private var c: UInt32 = 0x98BA_DCFE
    private var d: UInt32 = 0x1032_5476

    private var buffer = Data()           // partial block accumulator
    private var totalLength: UInt64 = 0   // message length in bytes

    mutating func update(_ data: Data) {
        totalLength += UInt64(data.count)
        buffer.append(data)

        // Process as many complete 64-byte blocks as we can.
        let blockCount = buffer.count / 64
        for i in 0..<blockCount {
            let block = buffer[buffer.startIndex + i * 64 ..< buffer.startIndex + i * 64 + 64]
            processBlock(Array(block))
        }
        // Keep the leftover bytes for next update / finalize.
        if blockCount > 0 {
            buffer = Data(buffer.suffix(from: buffer.startIndex + blockCount * 64))
        }
    }

    mutating func finalize() -> Data {
        // RFC 1320 §3.1–3.2: pad with 1-bit, zeros, then 64-bit length.
        var padded = buffer
        padded.append(0x80)
        while padded.count % 64 != 56 {
            padded.append(0x00)
        }
        // Append original message length in bits as little-endian UInt64.
        var bitLength = totalLength &* 8
        padded.append(Data(bytes: &bitLength, count: 8))

        // Process remaining blocks (1 or 2).
        let blockCount = padded.count / 64
        for i in 0..<blockCount {
            let block = padded[padded.startIndex + i * 64 ..< padded.startIndex + i * 64 + 64]
            processBlock(Array(block))
        }

        // Produce the 16-byte digest (little-endian).
        var digest = Data(count: 16)
        digest.withUnsafeMutableBytes { ptr in
            ptr.storeBytes(of: a.littleEndian, toByteOffset: 0,  as: UInt32.self)
            ptr.storeBytes(of: b.littleEndian, toByteOffset: 4,  as: UInt32.self)
            ptr.storeBytes(of: c.littleEndian, toByteOffset: 8,  as: UInt32.self)
            ptr.storeBytes(of: d.littleEndian, toByteOffset: 12, as: UInt32.self)
        }
        return digest
    }

    // MARK: - Block processing (RFC 1320 §3.4)

    private mutating func processBlock(_ bytes: [UInt8]) {
        // Decode 16 little-endian 32-bit words.
        var x = [UInt32](repeating: 0, count: 16)
        for i in 0..<16 {
            x[i] = UInt32(bytes[i * 4])
                  | UInt32(bytes[i * 4 + 1]) << 8
                  | UInt32(bytes[i * 4 + 2]) << 16
                  | UInt32(bytes[i * 4 + 3]) << 24
        }

        var aa = a, bb = b, cc = c, dd = d

        // ── Round 1 ────────────────────────────────────────────────────
        func F(_ x: UInt32, _ y: UInt32, _ z: UInt32) -> UInt32 { (x & y) | (~x & z) }

        aa = rotl(aa &+ F(bb, cc, dd) &+ x[ 0],  3); dd = rotl(dd &+ F(aa, bb, cc) &+ x[ 1],  7)
        cc = rotl(cc &+ F(dd, aa, bb) &+ x[ 2], 11); bb = rotl(bb &+ F(cc, dd, aa) &+ x[ 3], 19)
        aa = rotl(aa &+ F(bb, cc, dd) &+ x[ 4],  3); dd = rotl(dd &+ F(aa, bb, cc) &+ x[ 5],  7)
        cc = rotl(cc &+ F(dd, aa, bb) &+ x[ 6], 11); bb = rotl(bb &+ F(cc, dd, aa) &+ x[ 7], 19)
        aa = rotl(aa &+ F(bb, cc, dd) &+ x[ 8],  3); dd = rotl(dd &+ F(aa, bb, cc) &+ x[ 9],  7)
        cc = rotl(cc &+ F(dd, aa, bb) &+ x[10], 11); bb = rotl(bb &+ F(cc, dd, aa) &+ x[11], 19)
        aa = rotl(aa &+ F(bb, cc, dd) &+ x[12],  3); dd = rotl(dd &+ F(aa, bb, cc) &+ x[13],  7)
        cc = rotl(cc &+ F(dd, aa, bb) &+ x[14], 11); bb = rotl(bb &+ F(cc, dd, aa) &+ x[15], 19)

        // ── Round 2 ────────────────────────────────────────────────────
        func G(_ x: UInt32, _ y: UInt32, _ z: UInt32) -> UInt32 { (x & y) | (x & z) | (y & z) }
        let k2: UInt32 = 0x5A82_7999

        aa = rotl(aa &+ G(bb, cc, dd) &+ x[ 0] &+ k2,  3); dd = rotl(dd &+ G(aa, bb, cc) &+ x[ 4] &+ k2,  5)
        cc = rotl(cc &+ G(dd, aa, bb) &+ x[ 8] &+ k2,  9); bb = rotl(bb &+ G(cc, dd, aa) &+ x[12] &+ k2, 13)
        aa = rotl(aa &+ G(bb, cc, dd) &+ x[ 1] &+ k2,  3); dd = rotl(dd &+ G(aa, bb, cc) &+ x[ 5] &+ k2,  5)
        cc = rotl(cc &+ G(dd, aa, bb) &+ x[ 9] &+ k2,  9); bb = rotl(bb &+ G(cc, dd, aa) &+ x[13] &+ k2, 13)
        aa = rotl(aa &+ G(bb, cc, dd) &+ x[ 2] &+ k2,  3); dd = rotl(dd &+ G(aa, bb, cc) &+ x[ 6] &+ k2,  5)
        cc = rotl(cc &+ G(dd, aa, bb) &+ x[10] &+ k2,  9); bb = rotl(bb &+ G(cc, dd, aa) &+ x[14] &+ k2, 13)
        aa = rotl(aa &+ G(bb, cc, dd) &+ x[ 3] &+ k2,  3); dd = rotl(dd &+ G(aa, bb, cc) &+ x[ 7] &+ k2,  5)
        cc = rotl(cc &+ G(dd, aa, bb) &+ x[11] &+ k2,  9); bb = rotl(bb &+ G(cc, dd, aa) &+ x[15] &+ k2, 13)

        // ── Round 3 ────────────────────────────────────────────────────
        func H(_ x: UInt32, _ y: UInt32, _ z: UInt32) -> UInt32 { x ^ y ^ z }
        let k3: UInt32 = 0x6ED9_EBA1

        aa = rotl(aa &+ H(bb, cc, dd) &+ x[ 0] &+ k3,  3); dd = rotl(dd &+ H(aa, bb, cc) &+ x[ 8] &+ k3,  9)
        cc = rotl(cc &+ H(dd, aa, bb) &+ x[ 4] &+ k3, 11); bb = rotl(bb &+ H(cc, dd, aa) &+ x[12] &+ k3, 15)
        aa = rotl(aa &+ H(bb, cc, dd) &+ x[ 2] &+ k3,  3); dd = rotl(dd &+ H(aa, bb, cc) &+ x[10] &+ k3,  9)
        cc = rotl(cc &+ H(dd, aa, bb) &+ x[ 6] &+ k3, 11); bb = rotl(bb &+ H(cc, dd, aa) &+ x[14] &+ k3, 15)
        aa = rotl(aa &+ H(bb, cc, dd) &+ x[ 1] &+ k3,  3); dd = rotl(dd &+ H(aa, bb, cc) &+ x[ 9] &+ k3,  9)
        cc = rotl(cc &+ H(dd, aa, bb) &+ x[ 5] &+ k3, 11); bb = rotl(bb &+ H(cc, dd, aa) &+ x[13] &+ k3, 15)
        aa = rotl(aa &+ H(bb, cc, dd) &+ x[ 3] &+ k3,  3); dd = rotl(dd &+ H(aa, bb, cc) &+ x[11] &+ k3,  9)
        cc = rotl(cc &+ H(dd, aa, bb) &+ x[ 7] &+ k3, 11); bb = rotl(bb &+ H(cc, dd, aa) &+ x[15] &+ k3, 15)

        // Add this block's result to running totals.
        a = a &+ aa; b = b &+ bb; c = c &+ cc; d = d &+ dd
    }
}

// MARK: - Helpers

/// Left-rotate a 32-bit value by `s` bits.
@inline(__always)
private func rotl(_ value: UInt32, _ s: Int) -> UInt32 {
    (value << s) | (value >> (32 - s))
}
