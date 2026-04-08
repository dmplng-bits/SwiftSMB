//
//  SMB2Read.swift
//  SwiftSMB
//
//  Created by Preet Singh on 4/8/26.
//
// SMB2 READ request and response ([MS-SMB2] §2.2.19–2.2.20).
//
// READ is the core operation for video streaming.
// The local HTTP proxy translates AVPlayer's Range requests into
// SMB2 READ packets with the matching offset and length.

import Foundation

// MARK: - READ Request Builder

public enum SMB2ReadRequest {

    /// StructureSize for READ request is always 49.
    public static let structureSize: UInt16 = 49

    /// Build a READ request body.
    ///
    /// - `fileId`: The file handle from CREATE.
    /// - `offset`: Byte offset into the file to start reading.
    /// - `length`: Number of bytes to read.
    /// - `minimumCount`: Minimum bytes the server must return (default: 0).
    public static func build(
        fileId: SMB2FileId,
        offset: UInt64,
        length: UInt32,
        minimumCount: UInt32 = 0
    ) -> Data {
        // ReadChannelInfoOffset / Length — not used, set to 0.
        // Buffer — must contain at least 1 byte per spec (padding byte).
        let readChannelInfoOffset: UInt16 = 0
        let readChannelInfoLength: UInt16 = 0

        var w = ByteWriter()
        w.uint16le(structureSize)            // StructureSize (49)
        w.uint8(0)                           // Padding (for alignment)
        w.uint8(0)                           // Flags (0 for SMB 2.x/3.0.x)
        w.uint32le(length)                   // Length (bytes to read)
        w.uint64le(offset)                   // Offset
        fileId.write(to: &w)                 // FileId (16 bytes)
        w.uint32le(minimumCount)             // MinimumCount
        w.uint32le(0)                        // Channel (0 = none)
        w.uint32le(0)                        // RemainingBytes
        w.uint16le(readChannelInfoOffset)    // ReadChannelInfoOffset
        w.uint16le(readChannelInfoLength)    // ReadChannelInfoLength
        w.uint8(0)                           // Buffer (1-byte padding per spec)
        return w.data
    }
}

// MARK: - READ Response Parser

/// Parsed fields from a READ response body.
public struct SMB2ReadResponse {
    public let structureSize: UInt16
    public let dataOffset:    UInt8
    public let dataLength:    UInt32
    public let dataRemaining: UInt32
    public let data:          Data      // the actual file bytes
}

extension SMB2ReadResponse {

    /// Expected StructureSize for a READ response.
    public static let expectedStructureSize: UInt16 = 17

    /// Parse a READ response body (data after the 64-byte header).
    public static func parse(_ body: Data) throws -> SMB2ReadResponse {
        var r = ByteReader(body)

        let structureSize = try r.uint16le()
        let dataOffset    = try r.uint8()
        let _             = try r.uint8()      // Reserved
        let dataLength    = try r.uint32le()
        let dataRemaining = try r.uint32le()
        let _             = try r.uint32le()   // Reserved2

        // DataOffset is relative to the start of the SMB2 header.
        let localOffset = Int(dataOffset) - smb2HeaderSize
        let fileData: Data
        if dataLength > 0, localOffset >= 0, localOffset + Int(dataLength) <= body.count {
            fileData = Data(body[body.startIndex + localOffset ..< body.startIndex + localOffset + Int(dataLength)])
        } else if dataLength > 0 {
            // Fallback: read remaining bytes from current cursor position
            fileData = Data(r.rest().prefix(Int(dataLength)))
        } else {
            fileData = Data()
        }

        return SMB2ReadResponse(
            structureSize: structureSize,
            dataOffset:    dataOffset,
            dataLength:    dataLength,
            dataRemaining: dataRemaining,
            data:          fileData
        )
    }
}
