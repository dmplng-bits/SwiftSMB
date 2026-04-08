//
//  SMB2Session.swift
//  SwiftSMB
//
//  Created by Preet Singh on 4/8/26.
//
// SMB2 SESSION_SETUP request/response and LOGOFF ([MS-SMB2] §2.2.5–2.2.8).
//
// SESSION_SETUP carries the SPNEGO-wrapped NTLM tokens:
//   Request  → SPNEGO(NTLM Negotiate) or SPNEGO(NTLM Authenticate)
//   Response → SPNEGO(NTLM Challenge) or accept/reject
//
// The client may need multiple round-trips (STATUS_MORE_PROCESSING_REQUIRED).

import Foundation

// MARK: - SESSION_SETUP Request Builder

public enum SMB2SessionSetupRequest {

    /// StructureSize for SESSION_SETUP request is always 25.
    public static let structureSize: UInt16 = 25

    /// Build a SESSION_SETUP request body.
    ///
    /// - `securityBuffer`: The SPNEGO-wrapped NTLM token to send.
    /// - `sessionId`: 0 for the first request, or the previous sessionId
    ///   for subsequent round-trips.
    /// - `securityMode`: Signing mode (default: signing-enabled).
    /// - `capabilities`: Client capabilities (default: 0).
    /// - `previousSessionId`: For re-authentication (default: 0).
    public static func build(
        securityBuffer: Data,
        securityMode: UInt16 = SMB2SecurityMode.signingEnabled,
        capabilities: UInt32 = 0,
        previousSessionId: UInt64 = 0
    ) -> Data {
        // SecurityBufferOffset is relative to header start.
        // Header (64) + fixed body fields before buffer (24) = 88
        let securityBufferOffset: UInt16 = UInt16(smb2HeaderSize) + 24

        var w = ByteWriter()
        w.uint16le(structureSize)                    //  0..1  StructureSize (25)
        w.uint8(0)                                   //  2     Flags (0 = first request)
        w.uint8(UInt8(securityMode & 0xFF))          //  3     SecurityMode (1 byte)
        w.uint32le(capabilities)                     //  4..7  Capabilities
        w.uint32le(0)                                //  8..11 Channel (must be 0)
        w.uint16le(securityBufferOffset)             // 12..13 SecurityBufferOffset
        w.uint16le(UInt16(securityBuffer.count))     // 14..15 SecurityBufferLength
        w.uint64le(previousSessionId)                // 16..23 PreviousSessionId
        w.bytes(securityBuffer)                      // 24+    SecurityBuffer payload
        return w.data
    }
}

// MARK: - SESSION_SETUP Response Parser

/// Parsed fields from a SESSION_SETUP response body.
public struct SMB2SessionSetupResponse {
    public let structureSize:  UInt16
    public let sessionFlags:   UInt16
    public let securityBuffer: Data    // SPNEGO token from server
}

extension SMB2SessionSetupResponse {

    /// Expected StructureSize for a SESSION_SETUP response.
    public static let expectedStructureSize: UInt16 = 9

    /// Parse a SESSION_SETUP response body (data after the 64-byte header).
    public static func parse(_ data: Data) throws -> SMB2SessionSetupResponse {
        var r = ByteReader(data)

        let structureSize = try r.uint16le()
        let sessionFlags  = try r.uint16le()

        let securityBufferOffset = try r.uint16le()
        let securityBufferLength = try r.uint16le()

        let localOffset = Int(securityBufferOffset) - smb2HeaderSize
        let securityBuffer: Data
        if securityBufferLength > 0, localOffset >= 0, localOffset + Int(securityBufferLength) <= data.count {
            securityBuffer = Data(data[data.startIndex + localOffset ..< data.startIndex + localOffset + Int(securityBufferLength)])
        } else {
            securityBuffer = Data()
        }

        return SMB2SessionSetupResponse(
            structureSize:  structureSize,
            sessionFlags:   sessionFlags,
            securityBuffer: securityBuffer
        )
    }
}

// MARK: - LOGOFF Request Builder

public enum SMB2LogoffRequest {

    /// StructureSize for LOGOFF request is always 4.
    public static let structureSize: UInt16 = 4

    /// Build a LOGOFF request body. No payload — just the fixed 4-byte body.
    public static func build() -> Data {
        var w = ByteWriter()
        w.uint16le(structureSize)    // StructureSize (4)
        w.zeros(2)                   // Reserved
        return w.data
    }
}

// MARK: - LOGOFF Response Parser

/// Parsed LOGOFF response. Minimal — just the structure size.
public struct SMB2LogoffResponse {
    public let structureSize: UInt16
}

extension SMB2LogoffResponse {

    public static let expectedStructureSize: UInt16 = 4

    public static func parse(_ data: Data) throws -> SMB2LogoffResponse {
        var r = ByteReader(data)
        let structureSize = try r.uint16le()
        return SMB2LogoffResponse(structureSize: structureSize)
    }
}
