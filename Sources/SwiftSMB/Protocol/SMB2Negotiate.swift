//
//  SMB2Negotiate.swift
//  SwiftSMB
//
//  Created by Preet Singh on 4/8/26.
//
// SMB2 NEGOTIATE request and response ([MS-SMB2] §2.2.3 / §2.2.4).
//
// The client sends a NEGOTIATE with its supported dialects.
// The server replies with the chosen dialect, capabilities, and security blob.
//
// We negotiate SMB 2.0.2 through 3.1.1 and let the
// server pick the highest it supports.

import Foundation

// MARK: - NEGOTIATE Request Builder

public enum SMB2NegotiateRequest {

    /// The StructureSize for a NEGOTIATE request is always 36.
    public static let structureSize: UInt16 = 36

    /// Build a NEGOTIATE request body (everything after the 64-byte header).
    ///
    /// - `dialects`: The SMB2 dialects the client supports.
    ///   Defaults to [2.0.2, 2.1.0, 3.0.0, 3.0.2, 3.1.1].
    /// - `clientGuid`: A 16-byte GUID identifying this client instance.
    /// - `securityMode`: Signing capabilities. Defaults to signing-enabled.
    /// - `capabilities`: Client capabilities. Defaults to 0 (basic).
    /// - `preauthSalt`: 32 random bytes sent in the PreauthIntegrity
    ///   context. Required when 3.1.1 is offered. Ignored otherwise.
    public static func build(
        dialects: [UInt16] = [
            SMB2Dialect.smb202,
            SMB2Dialect.smb210,
            SMB2Dialect.smb300,
            SMB2Dialect.smb302,
            SMB2Dialect.smb311
        ],
        clientGuid: Data = randomGuid(),
        securityMode: UInt16 = SMB2SecurityMode.signingEnabled,
        capabilities: UInt32 = 0,
        preauthSalt: Data = randomSalt()
    ) -> Data {
        let offers311 = dialects.contains(SMB2Dialect.smb311)

        // Body up to (but not including) the dialect array and contexts.
        var w = ByteWriter()
        w.uint16le(structureSize)                // StructureSize (36)
        w.uint16le(UInt16(dialects.count))       // DialectCount
        w.uint16le(securityMode)                 // SecurityMode
        w.zeros(2)                               // Reserved
        w.uint32le(capabilities)                 // Capabilities
        w.bytes(clientGuid)                      // ClientGuid (16 bytes)

        if offers311 {
            // For 3.1.1, the 8-byte field at offset 28 of the body is:
            //   NegotiateContextOffset (4) + NegotiateContextCount (2) + Reserved2 (2)
            // NegotiateContextOffset is relative to the SMB2 header start.

            // We don't know the final offset yet — patch it after we
            // know the size of the dialect array plus padding.
            let contextOffsetPatchAt = w.data.count
            w.uint32le(0)                        // NegotiateContextOffset (patch)
            w.uint16le(2)                        // NegotiateContextCount (preauth + encryption)
            w.zeros(2)                           // Reserved2

            // Dialects array
            for d in dialects {
                w.uint16le(d)
            }

            // Pad to 8-byte alignment (relative to header start; the
            // header is 64 bytes so the body is already 8-aligned).
            let bodyLen = w.data.count
            let totalLen = smb2HeaderSize + bodyLen
            let pad = (8 - (totalLen % 8)) % 8
            if pad > 0 { w.zeros(pad) }

            // NegotiateContextOffset is header-relative.
            let contextOffset = UInt32(smb2HeaderSize + w.data.count)
            w.patchUint16le(UInt16(contextOffset & 0xFFFF),
                            at: contextOffsetPatchAt)
            w.patchUint16le(UInt16((contextOffset >> 16) & 0xFFFF),
                            at: contextOffsetPatchAt + 2)

            // Context 1: PreauthIntegrity (SHA-512 + 32-byte salt).
            appendPreauthIntegrityContext(&w, salt: preauthSalt)
            // 8-byte pad between contexts.
            let afterCtx1 = w.data.count
            let pad1 = (8 - (afterCtx1 % 8)) % 8
            if pad1 > 0 { w.zeros(pad1) }

            // Context 2: EncryptionCapabilities.
            appendEncryptionContext(&w)
        } else {
            // Legacy layout — ClientStartTime (8 bytes, must be zero).
            w.zeros(8)
            for d in dialects {
                w.uint16le(d)
            }
        }
        return w.data
    }

    // MARK: Negotiate context helpers

    private static func appendPreauthIntegrityContext(
        _ w: inout ByteWriter,
        salt: Data
    ) {
        // Data = HashAlgorithmCount(2) + SaltLength(2) + HashAlgorithms(2*N) + Salt(SaltLength)
        var data = ByteWriter()
        data.uint16le(1)                                          // HashAlgorithmCount
        data.uint16le(UInt16(salt.count))                         // SaltLength
        data.uint16le(SMB2HashAlgorithm.sha512)                   // HashAlgorithms[0]
        data.bytes(salt)                                          // Salt

        w.uint16le(SMB2NegotiateContext.preauthIntegrityCapabilities)
        w.uint16le(UInt16(data.data.count))                       // DataLength
        w.zeros(4)                                                // Reserved
        w.bytes(data.data)
    }

    private static func appendEncryptionContext(_ w: inout ByteWriter) {
        // Data = CipherCount(2) + Ciphers[CipherCount*2]
        var data = ByteWriter()
        data.uint16le(2)                                          // CipherCount
        data.uint16le(SMB2Cipher.aes128gcm)                       // preferred
        data.uint16le(SMB2Cipher.aes128ccm)

        w.uint16le(SMB2NegotiateContext.encryptionCapabilities)
        w.uint16le(UInt16(data.data.count))                       // DataLength
        w.zeros(4)                                                // Reserved
        w.bytes(data.data)
    }

    public static func randomGuid() -> Data {
        var bytes = [UInt8](repeating: 0, count: 16)
        _ = SecRandomCopyBytes(kSecRandomDefault, 16, &bytes)
        return Data(bytes)
    }

    public static func randomSalt() -> Data {
        var bytes = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, 32, &bytes)
        return Data(bytes)
    }
}

// MARK: - NEGOTIATE Response Parser

/// Parsed fields from an SMB2 NEGOTIATE response body.
public struct SMB2NegotiateResponse {
    public let structureSize: UInt16
    public let securityMode:  UInt16
    public let dialectRevision: UInt16
    public let serverGuid:    Data         // 16 bytes
    public let capabilities:  UInt32
    public let maxTransactSize: UInt32
    public let maxReadSize:   UInt32
    public let maxWriteSize:  UInt32
    public let systemTime:    UInt64       // Windows FILETIME
    public let serverStartTime: UInt64     // Windows FILETIME
    public let securityBuffer: Data        // SPNEGO token from server
    /// Cipher the server picked from our EncryptionCapabilities context
    /// (`SMB2Cipher.*`). Zero if the server didn't return that context
    /// or we negotiated a pre-3.1.1 dialect.
    public let chosenCipher:  UInt16
}

extension SMB2NegotiateResponse {

    /// Expected StructureSize for a NEGOTIATE response.
    public static let expectedStructureSize: UInt16 = 65

    /// Parse a NEGOTIATE response body (data after the 64-byte header).
    public static func parse(_ data: Data) throws -> SMB2NegotiateResponse {
        var r = ByteReader(data)

        let structureSize   = try r.uint16le()
        let securityMode    = try r.uint16le()
        let dialectRevision = try r.uint16le()

        // NegotiateContextCount (SMB 3.1.1) or Reserved (SMB 2.x/3.0.x)
        let negotiateContextCount = try r.uint16le()

        let serverGuid      = try r.bytes(16)
        let capabilities    = try r.uint32le()
        let maxTransactSize = try r.uint32le()
        let maxReadSize     = try r.uint32le()
        let maxWriteSize    = try r.uint32le()
        let systemTime      = try r.uint64le()
        let serverStartTime = try r.uint64le()

        // SecurityBufferOffset is relative to the start of the SMB2 header,
        // but we're parsing the body, so compute local offset.
        let securityBufferOffset = try r.uint16le()
        let securityBufferLength = try r.uint16le()

        // NegotiateContextOffset: where the response context list starts
        // (header-relative). Only meaningful on SMB 3.1.1.
        let negotiateContextOffset = try r.uint32le()

        // Extract security buffer using offset relative to the header start.
        // The offset includes the 64-byte header, so subtract it to get
        // the position within the body data.
        let localOffset = Int(securityBufferOffset) - smb2HeaderSize
        let securityBuffer: Data
        if securityBufferLength > 0, localOffset >= 0, localOffset + Int(securityBufferLength) <= data.count {
            securityBuffer = Data(data[data.startIndex + localOffset ..< data.startIndex + localOffset + Int(securityBufferLength)])
        } else {
            securityBuffer = Data()
        }

        // Parse NegotiateContextList (3.1.1 only) and extract the
        // cipher the server chose from our EncryptionCapabilities offer.
        var chosenCipher: UInt16 = 0
        if dialectRevision == SMB2Dialect.smb311, negotiateContextCount > 0 {
            let absOffset = Int(negotiateContextOffset)
            let localOffset = absOffset - smb2HeaderSize
            if localOffset >= 0, localOffset < data.count {
                chosenCipher = extractChosenCipher(
                    from: data,
                    startLocalOffset: localOffset,
                    contextCount: Int(negotiateContextCount)
                )
            }
        }

        return SMB2NegotiateResponse(
            structureSize:   structureSize,
            securityMode:    securityMode,
            dialectRevision: dialectRevision,
            serverGuid:      serverGuid,
            capabilities:    capabilities,
            maxTransactSize: maxTransactSize,
            maxReadSize:     maxReadSize,
            maxWriteSize:    maxWriteSize,
            systemTime:      systemTime,
            serverStartTime: serverStartTime,
            securityBuffer:  securityBuffer,
            chosenCipher:    chosenCipher
        )
    }

    /// Walk the NegotiateContextList looking for EncryptionCapabilities
    /// and return the server-selected cipher id, or 0 if absent.
    private static func extractChosenCipher(
        from data: Data,
        startLocalOffset: Int,
        contextCount: Int
    ) -> UInt16 {
        var cursor = startLocalOffset
        for _ in 0..<contextCount {
            // Each context: ContextType(2) + DataLength(2) + Reserved(4) + Data(DataLength) + 8-byte pad
            guard cursor + 8 <= data.count else { return 0 }
            let base = data.startIndex + cursor
            let type   = UInt16(data[base])     | UInt16(data[base + 1]) << 8
            let length = UInt16(data[base + 2]) | UInt16(data[base + 3]) << 8
            cursor += 8
            let dataStart = cursor
            guard dataStart + Int(length) <= data.count else { return 0 }

            if type == SMB2NegotiateContext.encryptionCapabilities,
               length >= 4 {
                // Data = CipherCount(2) + Ciphers[CipherCount*2]
                let ciphBase = data.startIndex + dataStart
                let count = UInt16(data[ciphBase]) | UInt16(data[ciphBase + 1]) << 8
                if count >= 1, length >= 4 {
                    return UInt16(data[ciphBase + 2]) | UInt16(data[ciphBase + 3]) << 8
                }
            }
            cursor += Int(length)
            // Pad to 8-byte alignment before next context.
            let pad = (8 - (cursor % 8)) % 8
            cursor += pad
        }
        return 0
    }
}
