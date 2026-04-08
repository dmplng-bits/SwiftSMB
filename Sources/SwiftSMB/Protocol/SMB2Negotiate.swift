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
    ///   Defaults to [2.0.2, 2.1.0, 3.0.0, 3.0.2].
    /// - `clientGuid`: A 16-byte GUID identifying this client instance.
    /// - `securityMode`: Signing capabilities. Defaults to signing-enabled.
    /// - `capabilities`: Client capabilities. Defaults to 0 (basic).
    public static func build(
        dialects: [UInt16] = [
            SMB2Dialect.smb202,
            SMB2Dialect.smb210,
            SMB2Dialect.smb300,
            SMB2Dialect.smb302
        ],
        clientGuid: Data = Data(count: 16),
        securityMode: UInt16 = SMB2SecurityMode.signingEnabled,
        capabilities: UInt32 = 0
    ) -> Data {
        var w = ByteWriter()
        w.uint16le(structureSize)                // StructureSize (36)
        w.uint16le(UInt16(dialects.count))       // DialectCount
        w.uint16le(securityMode)                 // SecurityMode
        w.zeros(2)                               // Reserved
        w.uint32le(capabilities)                 // Capabilities
        w.bytes(clientGuid)                      // ClientGuid (16 bytes)
        // ClientStartTime — must be 0 for SMB 2.x clients
        w.zeros(8)                               // ClientStartTime / NegotiateContextOffset + Count + Reserved2
        // Dialects array
        for d in dialects {
            w.uint16le(d)
        }
        return w.data
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
        let _ = try r.uint16le()

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

        // Skip NegotiateContextOffset (4 bytes, used only in SMB 3.1.1)
        try r.skip(4)

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
            securityBuffer:  securityBuffer
        )
    }
}
