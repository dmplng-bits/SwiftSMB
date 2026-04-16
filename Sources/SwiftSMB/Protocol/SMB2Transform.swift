//
//  SMB2Transform.swift
//  SwiftSMB
//
//  Created by Preet Singh on 4/15/26.
//
// SMB2 TRANSFORM_HEADER — the encrypted envelope that wraps every
// packet once a session or share enables encryption ([MS-SMB2] §2.2.41).
//
// Layout:
//   Offset 0    ProtocolId (4)   = 0xFD, 'S', 'M', 'B'
//   Offset 4    Signature (16)   = AES-GCM/CCM authentication tag
//   Offset 20   Nonce (16)       = first 11 bytes for CCM, first 12 for GCM
//   Offset 36   OriginalMessageSize (4)
//   Offset 40   Reserved (2)
//   Offset 42   Flags (2)        = 0x0001 (Encrypted) for all 3.x dialects
//   Offset 44   SessionId (8)
//   Offset 52   Ciphertext (...)
//
// Total header size = 52 bytes. The AAD for the AEAD cipher is the
// 32-byte range [20..52) — nonce + sizes + reserved + flags + sessionId.
//
// We only implement AES-128-GCM. AES-CCM support would require
// CommonCrypto's kCCModeCCM path; see the remaining-gap note at the
// bottom of this file.

import Foundation
import CryptoKit

// MARK: - Constants

public enum SMB2Transform {

    /// The "encrypted" marker that replaces the regular SMB2 protocol
    /// ID when a packet is wrapped in a TRANSFORM_HEADER.
    /// Bytes on the wire: 0xFD 'S' 'M' 'B'.
    public static let protocolId: UInt32 = 0x424D53FD

    /// Total size of the transform header (before ciphertext).
    public static let headerSize: Int = 52

    /// Flag value for 3.x dialects — 0x0001 means "encrypted".
    public static let flagEncrypted: UInt16 = 0x0001
}

// MARK: - Builder

public enum SMB2TransformBuilder {

    /// Wrap a fully-built SMB2 packet in a TRANSFORM_HEADER and encrypt
    /// it under AES-128-GCM.
    ///
    /// - `plaintext`: the raw SMB2 packet (header + body) to encrypt.
    /// - `encryptionKey`: 16-byte AES-128-GCM client-to-server key.
    /// - `sessionId`: the current session id.
    public static func buildGCM(
        plaintext: Data,
        encryptionKey: Data,
        sessionId: UInt64
    ) throws -> Data {
        // 11-byte nonce for CCM or 12-byte for GCM, zero-padded to 16.
        // We always use 12 random bytes + 4 zero bytes. This matches
        // Windows behavior and is spec-compliant for GCM.
        var nonce16 = Data(count: 16)
        var random = [UInt8](repeating: 0, count: 12)
        _ = SecRandomCopyBytes(kSecRandomDefault, 12, &random)
        for i in 0..<12 { nonce16[i] = random[i] }

        // Build the 32-byte AAD (everything from the Nonce field to the
        // end of the transform header). The ProtocolId (offset 0..3)
        // and Signature field (offset 4..19) are excluded.
        var aad = Data()
        aad.append(nonce16)                                   // 16
        aad.append(UInt32LE(UInt32(plaintext.count)))         //  4
        aad.append(UInt16LE(0))                               //  2 Reserved
        aad.append(UInt16LE(SMB2Transform.flagEncrypted))     //  2 Flags
        aad.append(UInt64LE(sessionId))                       //  8
        precondition(aad.count == 32)

        let key = SymmetricKey(data: encryptionKey)
        let gcmNonce = try AES.GCM.Nonce(data: nonce16.prefix(12))
        let sealed = try AES.GCM.seal(
            plaintext,
            using: key,
            nonce: gcmNonce,
            authenticating: aad
        )

        // Assemble the transform packet: ProtocolId + Signature + AAD + Ciphertext.
        var out = Data()
        out.append(UInt32LE(SMB2Transform.protocolId))        //  4
        out.append(Data(sealed.tag))                          // 16 (Signature)
        out.append(aad)                                       // 32 (offset 20..52)
        out.append(sealed.ciphertext)                         //  N
        return out
    }
}

// MARK: - Parser

public enum SMB2TransformParser {

    /// A parsed transform header plus the raw ciphertext that follows.
    public struct Parsed {
        public let signature:           Data   // 16 bytes (AEAD tag)
        public let nonce:               Data   // 16 bytes (first 12 used for GCM)
        public let originalMessageSize: UInt32
        public let flags:               UInt16
        public let sessionId:           UInt64
        /// AAD that was fed into the AEAD cipher — 32 bytes starting at offset 20.
        public let aad:        Data
        public let ciphertext: Data
    }

    /// Return `true` if the data starts with the transform protocol id.
    public static func isTransformPacket(_ data: Data) -> Bool {
        guard data.count >= 4 else { return false }
        let b = data.startIndex
        return data[b] == 0xFD
            && data[b + 1] == 0x53   // 'S'
            && data[b + 2] == 0x4D   // 'M'
            && data[b + 3] == 0x42   // 'B'
    }

    public static func parse(_ data: Data) throws -> Parsed {
        guard data.count >= SMB2Transform.headerSize else {
            throw SMBError.truncatedPacket
        }
        guard isTransformPacket(data) else {
            throw SMBError.invalidProtocolId
        }
        var r = ByteReader(data)
        try r.skip(4)                                           // ProtocolId
        let signature = try r.bytes(16)
        let aadStart = 20
        let nonce = try r.bytes(16)
        let originalMessageSize = try r.uint32le()
        _ = try r.uint16le()                                    // Reserved
        let flags = try r.uint16le()
        let sessionId = try r.uint64le()

        let aad = data.subdata(
            in: data.startIndex + aadStart ..< data.startIndex + SMB2Transform.headerSize
        )
        let ciphertext = data.subdata(
            in: data.startIndex + SMB2Transform.headerSize ..< data.endIndex
        )

        return Parsed(
            signature:           Data(signature),
            nonce:               Data(nonce),
            originalMessageSize: originalMessageSize,
            flags:               flags,
            sessionId:           sessionId,
            aad:                 aad,
            ciphertext:          ciphertext
        )
    }

    /// Decrypt a transform-wrapped packet under AES-128-GCM.
    /// The ciphertext contains the 16-byte tag at its tail — but we've
    /// already split the tag into `signature` during `parse`. CryptoKit
    /// expects tag and ciphertext separately.
    public static func decryptGCM(
        _ parsed: Parsed,
        decryptionKey: Data
    ) throws -> Data {
        let key = SymmetricKey(data: decryptionKey)
        let nonce = try AES.GCM.Nonce(data: parsed.nonce.prefix(12))
        let sealed = try AES.GCM.SealedBox(
            nonce: nonce,
            ciphertext: parsed.ciphertext,
            tag: parsed.signature
        )
        return try AES.GCM.open(sealed, using: key, authenticating: parsed.aad)
    }
}

// MARK: - Small LE helpers

private func UInt16LE(_ v: UInt16) -> Data {
    Data([UInt8(v & 0xFF), UInt8((v >> 8) & 0xFF)])
}

private func UInt32LE(_ v: UInt32) -> Data {
    Data([
        UInt8( v        & 0xFF),
        UInt8((v >>  8) & 0xFF),
        UInt8((v >> 16) & 0xFF),
        UInt8((v >> 24) & 0xFF),
    ])
}

private func UInt64LE(_ v: UInt64) -> Data {
    var d = Data(count: 8)
    for i in 0..<8 { d[i] = UInt8((v >> (i * 8)) & 0xFF) }
    return d
}

// MARK: - Known gap
//
// AES-128-CCM is not implemented. SMB 3.0 and 3.0.2 only offer CCM
// (GCM was added in 3.1.1), so this client can only complete encrypted
// traffic against a 3.1.1 server that picks AES-128-GCM. Servers that
// insist on CCM will fail the sealed exchange. A follow-up can wire
// CCM via CommonCrypto's kCCModeCCM.
