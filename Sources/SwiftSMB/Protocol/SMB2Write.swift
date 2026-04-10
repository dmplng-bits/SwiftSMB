//
//  SMB2Write.swift
//  SwiftSMB
//
//  Created by Preet Singh on 4/9/26.
//
// SMB2 WRITE request and response ([MS-SMB2] §2.2.21–2.2.22).
//
// WRITE is the core operation for uploading and modifying files.
// The client sends WRITE packets with the data to be written, the file offset,
// and the number of bytes. The server responds with the number of bytes written.

import Foundation

// MARK: - WRITE Request Builder

public enum SMB2WriteRequest {

    /// StructureSize for WRITE request is always 49.
    public static let structureSize: UInt16 = 49

    /// Build a WRITE request body.
    ///
    /// - `fileId`: The file handle from CREATE.
    /// - `offset`: Byte offset into the file where data starts.
    /// - `data`: The bytes to write to the file.
    public static func build(
        fileId: SMB2FileId,
        offset: UInt64,
        data: Data
    ) -> Data {
        // The fixed fields before the buffer are:
        // StructureSize(2) + DataOffset(2) + Length(4) + Offset(8) +
        // FileId(16) + Channel(4) + RemainingBytes(4) +
        // WriteChannelInfoOffset(2) + WriteChannelInfoLength(2) + Flags(4) = 48 bytes
        // So DataOffset = smb2HeaderSize (64) + 48 = 112
        let dataOffset: UInt16 = UInt16(smb2HeaderSize) + 48
        let writeChannelInfoOffset: UInt16 = 0
        let writeChannelInfoLength: UInt16 = 0

        var w = ByteWriter()
        w.uint16le(structureSize)                // StructureSize (49)
        w.uint16le(dataOffset)                   // DataOffset
        w.uint32le(UInt32(data.count))           // Length (bytes to write)
        w.uint64le(offset)                       // Offset
        fileId.write(to: &w)                     // FileId (16 bytes)
        w.uint32le(0)                            // Channel (0 = none)
        w.uint32le(0)                            // RemainingBytes (0)
        w.uint16le(writeChannelInfoOffset)       // WriteChannelInfoOffset
        w.uint16le(writeChannelInfoLength)       // WriteChannelInfoLength
        w.uint32le(0)                            // Flags (0)
        w.bytes(data)                            // Buffer (actual data)
        return w.data
    }
}

// MARK: - WRITE Response Parser

/// Parsed fields from a WRITE response body.
public struct SMB2WriteResponse {
    public let structureSize: UInt16
    public let count: UInt32        // bytes actually written
    public let remaining: UInt32
    public let writeChannelInfoOffset: UInt16
    public let writeChannelInfoLength: UInt16
}

extension SMB2WriteResponse {

    /// Expected StructureSize for a WRITE response.
    public static let expectedStructureSize: UInt16 = 17

    /// Parse a WRITE response body (data after the 64-byte header).
    public static func parse(_ body: Data) throws -> SMB2WriteResponse {
        var r = ByteReader(body)

        let structureSize = try r.uint16le()
        let _             = try r.uint16le()    // Reserved
        let count         = try r.uint32le()
        let remaining     = try r.uint32le()
        let writeChannelInfoOffset = try r.uint16le()
        let writeChannelInfoLength = try r.uint16le()

        return SMB2WriteResponse(
            structureSize: structureSize,
            count: count,
            remaining: remaining,
            writeChannelInfoOffset: writeChannelInfoOffset,
            writeChannelInfoLength: writeChannelInfoLength
        )
    }
}
