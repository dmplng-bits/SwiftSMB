//
//  SMB2Close.swift
//  SwiftSMB
//
//  Created by Preet Singh on 4/8/26.
//
// SMB2 CLOSE request and response ([MS-SMB2] §2.2.15–2.2.16).
//
// CLOSE releases a FileId obtained from CREATE. Always close handles
// when done to avoid resource leaks on the server.

import Foundation

// MARK: - CLOSE Request Builder

public enum SMB2CloseRequest {

    /// StructureSize for CLOSE request is always 24.
    public static let structureSize: UInt16 = 24

    /// Build a CLOSE request body.
    ///
    /// - `fileId`: The file handle to close.
    /// - `flags`: Set `SMB2CloseFlags.postQueryAttributes` to get
    ///   final file attributes in the response.
    public static func build(
        fileId: SMB2FileId,
        flags: UInt16 = 0
    ) -> Data {
        var w = ByteWriter()
        w.uint16le(structureSize)    // StructureSize (24)
        w.uint16le(flags)            // Flags
        w.zeros(4)                   // Reserved
        fileId.write(to: &w)         // FileId (16 bytes)
        return w.data
    }
}

// MARK: - CLOSE Response Parser

/// Parsed fields from a CLOSE response body.
public struct SMB2CloseResponse {
    public let structureSize:  UInt16
    public let flags:          UInt16
    public let creationTime:   UInt64
    public let lastAccessTime: UInt64
    public let lastWriteTime:  UInt64
    public let changeTime:     UInt64
    public let allocationSize: UInt64
    public let endOfFile:      UInt64
    public let fileAttributes: UInt32
}

extension SMB2CloseResponse {

    /// Expected StructureSize for a CLOSE response.
    public static let expectedStructureSize: UInt16 = 60

    /// Parse a CLOSE response body (data after the 64-byte header).
    public static func parse(_ data: Data) throws -> SMB2CloseResponse {
        var r = ByteReader(data)

        let structureSize  = try r.uint16le()
        let flags          = try r.uint16le()
        let _              = try r.uint32le()  // Reserved
        let creationTime   = try r.uint64le()
        let lastAccessTime = try r.uint64le()
        let lastWriteTime  = try r.uint64le()
        let changeTime     = try r.uint64le()
        let allocationSize = try r.uint64le()
        let endOfFile      = try r.uint64le()
        let fileAttributes = try r.uint32le()

        return SMB2CloseResponse(
            structureSize:  structureSize,
            flags:          flags,
            creationTime:   creationTime,
            lastAccessTime: lastAccessTime,
            lastWriteTime:  lastWriteTime,
            changeTime:     changeTime,
            allocationSize: allocationSize,
            endOfFile:      endOfFile,
            fileAttributes: fileAttributes
        )
    }
}
